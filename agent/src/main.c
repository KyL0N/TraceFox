#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "tracefox.h"

/* Generate extern declarations */
#include "collector_list.def"
#define COLLECTOR(name) extern struct tf_collector name##_collector;
COLLECTOR_LIST
#undef COLLECTOR

/* Generate pointer array */
static struct tf_collector *g_collectors[] = {
#define COLLECTOR(name) &name##_collector,
	COLLECTOR_LIST
#undef COLLECTOR
	    NULL /* End of collectors */
};

static volatile sig_atomic_t keep_running       = 1;
static volatile sig_atomic_t reload_config_flag = 0;
enum tf_log_level g_tf_log_level                = TF_LOG_LVL_INFO;

static const char *const config_search_paths[] = {
	"config/agent.conf",
	"agent/config/agent.conf",
	"/etc/tracefox/agent.conf",
	NULL,
};

static void handle_signal(int sig)
{
	if (sig == SIGHUP) {
		reload_config_flag = 1;
	}
	else {
		keep_running = 0;
	}
}

static void config_defaults(struct agent_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	strncpy(cfg->server_host, TF_DEFAULT_SERVER_HOST, sizeof(cfg->server_host) - 1);
	cfg->server_port  = TF_DEFAULT_SERVER_PORT;
	cfg->interval_sec = TF_DEFAULT_INTERVAL_SEC;
}

static int is_ascii_safe(const char *value)
{
	if (!value) {
		return 0;
	}

	for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
		if (*cursor < 0x20U || *cursor > 0x7EU) {
			return 0;
		}
	}

	return 1;
}

static int resolve_addr(const char *host, uint16_t port, struct sockaddr_storage *addr, socklen_t *addr_len, int *family)
{
	char port_buf[6]         = { 0 };
	struct addrinfo hints    = { 0 };
	struct addrinfo *results = NULL;
	struct addrinfo *cursor  = NULL;

	if (!host || !addr || !addr_len || !family) {
		return -1;
	}

	(void)snprintf(port_buf, sizeof(port_buf), "%u", (unsigned)port);

	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	int rc = getaddrinfo(host, port_buf, &hints, &results);
	if (rc != 0) {
		TF_LOG_ERR("getaddrinfo(%s:%s): %s", host, port_buf, gai_strerror(rc));
		return -1;
	}

	for (cursor = results; cursor != NULL; cursor = cursor->ai_next) {
		if ((cursor->ai_family != AF_INET && cursor->ai_family != AF_INET6) || cursor->ai_addrlen > sizeof(*addr)) {
			continue;
		}

		memset(addr, 0, sizeof(*addr));
		memcpy(addr, cursor->ai_addr, cursor->ai_addrlen);
		*addr_len = (socklen_t)cursor->ai_addrlen;
		*family   = cursor->ai_family;
		freeaddrinfo(results);
		return 0;
	}

	freeaddrinfo(results);
	return -1;
}

static char *trim_inplace(char *string)
{
	char *end = NULL;

	while (*string && isspace((unsigned char)*string)) {
		++string;
	}

	if (*string == '\0') {
		return string;
	}

	end = string + strlen(string) - 1;
	while (end > string && isspace((unsigned char)*end)) {
		*end-- = '\0';
	}

	return string;
}

static const char *find_config_file(void)
{
	for (int i = 0; config_search_paths[i] != NULL; ++i) {
		if (access(config_search_paths[i], R_OK) == 0) {
			return config_search_paths[i];
		}
	}
	return NULL;
}

/* Returns 0 on success, -1 if file cannot be opened. */
static int load_config_file(const char *path, struct agent_config *cfg)
{
	FILE *config_fp              = NULL;
	char line[TF_LINE_BUF_SMALL] = { 0 };
	unsigned int line_no         = 0;

	config_fp = fopen(path, "r");
	if (!config_fp) {
		return -1;
	}

	while (fgets(line, sizeof(line), config_fp) != NULL) {
		char *key   = NULL;
		char *val   = NULL;
		char *eqs   = NULL;
		long parsed = 0;

		++line_no;
		key = trim_inplace(line);
		if (*key == '\0' || *key == '#') {
			continue;
		}

		eqs = strchr(key, '=');
		if (!eqs) {
			TF_LOG_DBG("[config] ignore invalid line %u: %s", line_no, key);
			continue;
		}
		*eqs = '\0';
		val  = trim_inplace(eqs + 1);
		key  = trim_inplace(key);

		if (strcmp(key, "server_host") == 0) {
			if (*val != '\0') {
				(void)strncpy(cfg->server_host, val, sizeof(cfg->server_host) - 1);
			}
		}
		else if (strcmp(key, "server_port") == 0) {
			errno  = 0;
			parsed = strtol(val, NULL, 10);

			if (errno == 0 && parsed > 0 && parsed <= 65535) {
				cfg->server_port = (uint16_t)parsed;
			}
			else {
				TF_LOG_DBG("[config] invalid server_port at line %u: %s", line_no, val);
			}
		}
		else if (strcmp(key, "interval") == 0) {
			errno  = 0;
			parsed = strtol(val, NULL, 10);

			if (errno == 0 && parsed > 0 && parsed <= 65535) {
				cfg->interval_sec = (uint16_t)parsed;
			}
			else {
				TF_LOG_DBG("[config] invalid interval at line %u: %s", line_no, val);
			}
		}
		else if (strcmp(key, "host_label") == 0) {
			if (*val == '\0') {
				cfg->host_label[0] = '\0';
			}
			else if (!is_ascii_safe(val)) {
				TF_LOG_WARN("[config] invalid host_label at line %u: ASCII printable characters only", line_no);
			}
			else {
				(void)strncpy(cfg->host_label, val, sizeof(cfg->host_label) - 1);
				cfg->host_label[sizeof(cfg->host_label) - 1] = '\0';
			}
		}
		else if (strcmp(key, "proc_prefix") == 0) {
			char *saveptr = NULL;
			char *prefix  = strtok_r(val, ",", &saveptr);

			while (prefix) {
				prefix = trim_inplace(prefix);
				if (*prefix != '\0') {
					config_add_proc_prefix(cfg, prefix);
				}
				prefix = strtok_r(NULL, ",", &saveptr);
			}
		}
	}

	(void)fclose(config_fp);
	return 0;
}

static void print_effective_config(const struct agent_config *cfg)
{
	TF_LOG_DBG("[config] effective: server_host=%s server_port=%u interval=%u host_label=%s", cfg->server_host,
	           (unsigned)cfg->server_port, (unsigned)cfg->interval_sec, cfg->host_label[0] != '\0' ? cfg->host_label : "<unset>");
}

static void config_init_from_sources(int argc, char **argv, struct agent_config *cfg)
{
	const char *explicit_path = NULL;

	config_defaults(cfg);

	/* Scan argv for -c before getopt to avoid disturbing global optind state */
	for (int i = 1; i < argc - 1; ++i) {
		if (strcmp(argv[i], "-c") == 0 && argv[i + 1] != NULL && argv[i + 1][0] != '\0') {
			explicit_path = argv[i + 1];
			break;
		}
	}

	if (explicit_path) {
		if (load_config_file(explicit_path, cfg) != 0) {
			TF_LOG_ERR("[config] fatal: cannot open '%s': %s", explicit_path, strerror(errno));
			exit(1);
		}
		TF_LOG_INFO("[config] loaded: %s", explicit_path);
	}
	else {
		const char *found = find_config_file();
		if (found) {
			(void)load_config_file(found, cfg);
			TF_LOG_INFO("[config] loaded: %s", found);
		}
		else {
			TF_LOG_INFO("[config] no config file found, using defaults");
		}
	}
}

static int sock          = -1;
static int file_mode     = 0;
static char *output_file = NULL;
static FILE *log_file    = NULL;
static struct sockaddr_storage dest_addr;
static socklen_t dest_addr_len = 0;

static int init_agent_state(int argc, char **argv, struct agent_config *cfg)
{
	int opt = 0;
	optind = 1;
	config_init_from_sources(argc, argv, cfg);

	while ((opt = getopt(argc, argv, "c:h:p:i:f:P:v")) != -1) {
		switch (opt) {
		case 'c': break;
		case 'h': (void)strncpy(cfg->server_host, optarg, sizeof(cfg->server_host) - 1); break;
		case 'p': cfg->server_port = (uint16_t)strtol(optarg, NULL, 10); break;
		case 'i':
			cfg->interval_sec = (uint16_t)strtol(optarg, NULL, 10);
			if (cfg->interval_sec == 0) cfg->interval_sec = 1U;
			break;
		case 'f':
			file_mode   = 1;
			output_file = optarg;
			break;
		case 'P': {
			char *saveptr = NULL;
			char *prefix  = strtok_r(optarg, ",", &saveptr);
			while (prefix) {
				prefix = trim_inplace(prefix);
				if (*prefix != '\0') config_add_proc_prefix(cfg, prefix);
				prefix = strtok_r(NULL, ",", &saveptr);
			}
			break;
		}
		case 'v': g_tf_log_level = TF_LOG_LVL_DBG; break;
		default: TF_LOG_ERR("Usage: %s [-c config] [-h host] [-p port] [-i interval] [-f file] [-P proc_prefix1,...] [-v]", argv[0]); return 1;
		}
	}

	print_effective_config(cfg);

	for (int i = 0; g_collectors[i] != NULL; i++) {
		if (g_collectors[i]->init) {
			int rc = g_collectors[i]->init(g_collectors[i], cfg);
			if (rc != 0) {
				TF_LOG_ERR("[%s] init failed (rc=%d), aborting", g_collectors[i]->name, rc);
				return 1;
			}
		}
	}

	if (file_mode) {
		log_file = fopen(output_file, "ab");
		if (!log_file) {
			TF_LOG_ERR("fopen(%s): %s", output_file, strerror(errno));
			return 1;
		}
		(void)fseek(log_file, 0, SEEK_END);
		if (ftell(log_file) == 0) {
			char header[TF_HEADER_LEN] = { 'T', 'F', 'O', 'X', TF_HEADER_VER, 0x00, 0x00, 0x00 };
			(void)fwrite(header, 1, TF_HEADER_LEN, log_file);
		}
	}
	else {
		int dest_family = AF_UNSPEC;
		if (resolve_addr(cfg->server_host, cfg->server_port, &dest_addr, &dest_addr_len, &dest_family) != 0) {
			TF_LOG_ERR("Failed to resolve %s:%u", cfg->server_host, (unsigned)cfg->server_port);
			return 1;
		}

		sock = socket(dest_family, SOCK_DGRAM, 0);
		if (sock < 0) {
			TF_LOG_ERR("socket: %s", strerror(errno));
			return 1;
		}
	}
	return 0;
}

static void destroy_agent_state(void)
{
	if (file_mode && log_file) {
		(void)fclose(log_file);
		log_file = NULL;
	}
	else if (sock >= 0) {
		close(sock);
		sock = -1;
	}

	for (int i = 0; g_collectors[i] != NULL; i++) {
		if (g_collectors[i]->destroy) {
			g_collectors[i]->destroy(g_collectors[i]);
		}
	}
}

int main(int argc, char **argv)
{
	uint32_t seq      = 0;

	uint8_t buffer[TF_FRAME_BUF_SIZE] = { 0 };
	struct agent_config cfg           = { 0 };
	struct tlv_writer writer          = { 0 };

	(void)signal(SIGINT, handle_signal);
	(void)signal(SIGTERM, handle_signal);
	(void)signal(SIGHUP, handle_signal);

	if (init_agent_state(argc, argv, &cfg) != 0) {
		return 1;
	}

	while (keep_running) {
		if (reload_config_flag) {
			reload_config_flag = 0;
			TF_LOG_INFO("SIGHUP received, reloading configuration...");
			destroy_agent_state();
			if (init_agent_state(argc, argv, &cfg) != 0) {
				TF_LOG_ERR("Failed to reload configuration, exiting");
				return 1;
			}
			TF_LOG_INFO("Configuration reloaded successfully");
			continue;
		}

		uint32_t timestamp = (uint32_t)time(NULL);

		if (tlv_init(&writer, buffer, sizeof(buffer), timestamp, seq++) != 0) {
			break;
		}

		if (cfg.host_label[0] != '\0') {
			size_t host_label_len = strnlen(cfg.host_label, sizeof(cfg.host_label));
			if (host_label_len > (size_t)UINT8_MAX) {
				host_label_len = (size_t)UINT8_MAX;
			}

			if (tlv_put(&writer, TF_TYPE_HOST_LABEL, cfg.host_label, (uint8_t)host_label_len) != 0) {
				TF_LOG_WARN("[host] failed to append host label TLV");
			}
		}

		unsigned long push_errors  = 0;
		struct sample_context sctx = { .cpu_total_diff = 1 };

		for (int i = 0; g_collectors[i] != NULL; i++) {
			struct tf_collector *col = g_collectors[i];
			if (col->collect) {
				int err = col->collect(col, &cfg, &sctx);
				if (err != 0) {
					TF_LOG_DBG("[%s] collect failed with err: %d", col->name, err);
				}
			}
		}

		for (int i = 0; g_collectors[i] != NULL; i++) {
			struct tf_collector *col = g_collectors[i];
			if (col->push) {
				int err = col->push(col, &writer);
				if (err != 0) {
					TF_LOG_ERR("[%s] push failed with err: %d", col->name, err);
					push_errors++;
				}
			}
		}

		if (g_tf_log_level >= TF_LOG_LVL_DBG) {
			TF_LOG_DBG("==== tracefox-agent sample @ %u (tlv_errors=%lu) ====", timestamp, push_errors);
			for (int i = 0; g_collectors[i] != NULL; i++) {
				struct tf_collector *col = g_collectors[i];
				if (col->print) {
					col->print(col, stderr);
				}
			}
		}

		if (file_mode) {
			uint16_t frame_len = (uint16_t)writer.len;
			uint8_t len_bytes[TF_FRAME_LEN_BYTES];
			uint8_t *lp = len_bytes;
			buf_put_be_u16(&lp, frame_len);
			(void)fwrite(len_bytes, 1, TF_FRAME_LEN_BYTES, log_file);
			(void)fwrite(buffer, 1, writer.len, log_file);
			(void)fflush(log_file);
		}
		else {
			ssize_t sent = sendto(sock, buffer, writer.len, 0, (const struct sockaddr *)&dest_addr, dest_addr_len);
			if (sent < 0) {
				push_errors++;
			}
		}
		
		unsigned int sleep_left = cfg.interval_sec;
		while (sleep_left > 0 && keep_running && !reload_config_flag) {
			sleep_left = sleep(sleep_left);
		}
	}

	destroy_agent_state();

	return 0;
}
