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
#include <stdbool.h>
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

static volatile sig_atomic_t keep_running = 1;
static bool verbose                       = false;

static const char *const config_search_paths[] = {
	"config/agent.conf",
	"agent/config/agent.conf",
	"/etc/tracefox/agent.conf",
	NULL,
};

static void handle_signal(int sig)
{
	(void)sig;
	keep_running = 0;
}

static void config_defaults(struct agent_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	strncpy(cfg->server_host, TF_DEFAULT_SERVER_HOST, sizeof(cfg->server_host) - 1);
	cfg->server_port  = TF_DEFAULT_SERVER_PORT;
	cfg->interval_sec = TF_DEFAULT_INTERVAL_SEC;
}

static int resolve_addr(const char *host, uint16_t port, struct sockaddr_in *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port   = htons(port);

	if (inet_pton(AF_INET, host, &addr->sin_addr) != 1) {
		return -1;
	}

	return 0;
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
			if (verbose) {
				(void)fprintf(stderr, "[config] ignore invalid line %u: %s\n", line_no, key);
			}
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
			else if (verbose) {
				(void)fprintf(stderr, "[config] invalid server_port at line %u: %s\n", line_no, val);
			}
		}
		else if (strcmp(key, "interval") == 0) {
			errno  = 0;
			parsed = strtol(val, NULL, 10);

			if (errno == 0 && parsed > 0 && parsed <= 65535) {
				cfg->interval_sec = (uint16_t)parsed;
			}
			else if (verbose) {
				(void)fprintf(stderr, "[config] invalid interval at line %u: %s\n", line_no, val);
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
	(void)fprintf(stderr, "[config] effective: server_host=%s server_port=%u interval=%u\n", cfg->server_host, (unsigned)cfg->server_port,
	              (unsigned)cfg->interval_sec);
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
			(void)fprintf(stderr, "[config] fatal: cannot open '%s': %s\n", explicit_path, strerror(errno));
			exit(1);
		}
		(void)fprintf(stderr, "[config] loaded: %s\n", explicit_path);
	}
	else {
		const char *found = find_config_file();
		if (found) {
			(void)load_config_file(found, cfg);
			(void)fprintf(stderr, "[config] loaded: %s\n", found);
		}
		else {
			(void)fprintf(stderr, "[config] no config file found, using defaults\n");
		}
	}
}

int main(int argc, char **argv)
{
	int opt           = 0;
	int sock          = -1;
	int file_mode     = 0;
	uint32_t seq      = 0;
	char *output_file = NULL;
	FILE *log_file    = NULL;

	uint8_t buffer[TF_FRAME_BUF_SIZE] = { 0 };
	struct sockaddr_in dest           = { 0 };
	struct agent_config cfg           = { 0 };
	struct tlv_writer writer          = { 0 };

	/*
	 * Lifecycle: defaults -> proc init (needed by config parser for proc_add_comm_prefix)
	 * -> config file + CLI -> remaining collector inits (with full config)
	 */
	config_init_from_sources(argc, argv, &cfg);

	while ((opt = getopt(argc, argv, "c:h:p:i:f:P:v")) != -1) {
		switch (opt) {
		case 'c': break;
		case 'h': (void)strncpy(cfg.server_host, optarg, sizeof(cfg.server_host) - 1); break;
		case 'p': cfg.server_port = (uint16_t)strtol(optarg, NULL, 10); break;
		case 'i':
			cfg.interval_sec = (uint16_t)strtol(optarg, NULL, 10);
			if (cfg.interval_sec == 0) {
				cfg.interval_sec = 1U;
			}
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
				if (*prefix != '\0') {
					config_add_proc_prefix(&cfg, prefix);
				}
				prefix = strtok_r(NULL, ",", &saveptr);
			}
			break;
		}
		case 'v': verbose = true; break;
		default: (void)fprintf(stderr, "Usage: %s [-c config] [-h host] [-p port] [-i interval] [-f file] [-P proc_prefix1,...] [-v]\n", argv[0]); return 1;
		}
	}

	if (verbose) {
		print_effective_config(&cfg);
	}

	for (int i = 0; g_collectors[i] != NULL; i++) {
		if (g_collectors[i]->init) {
			int rc = g_collectors[i]->init(g_collectors[i], &cfg);
			if (rc != 0) {
				(void)fprintf(stderr, "[%s] init failed (rc=%d), aborting\n", g_collectors[i]->name, rc);
				return 1;
			}
		}
	}

	(void)signal(SIGINT, handle_signal);
	(void)signal(SIGTERM, handle_signal);

	if (file_mode) {
		log_file = fopen(output_file, "ab");
		if (!log_file) {
			perror("fopen");
			return 1;
		}
		(void)fseek(log_file, 0, SEEK_END);
		if (ftell(log_file) == 0) {
			char header[TF_HEADER_LEN] = { 'T', 'F', 'O', 'X', TF_HEADER_VER, 0x00, 0x00, 0x00 };
			(void)fwrite(header, 1, TF_HEADER_LEN, log_file);
		}
	}
	else {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0) {
			perror("socket");
			return 1;
		}

		if (resolve_addr(cfg.server_host, cfg.server_port, &dest) != 0) {
			(void)fprintf(stderr, "Failed to resolve %s\n", cfg.server_host);
			close(sock);
			return 1;
		}
	}

	while (keep_running) {
		uint32_t timestamp = (uint32_t)time(NULL);

		if (tlv_init(&writer, buffer, sizeof(buffer), timestamp, seq++) != 0) {
			break;
		}

		unsigned long push_errors  = 0;
		struct sample_context sctx = { .cpu_total_diff = 1 };

		for (int i = 0; g_collectors[i] != NULL; i++) {
			struct tf_collector *col = g_collectors[i];
			if (col->collect_and_push) {
				int err = col->collect_and_push(col, &writer, &cfg, &sctx);
				if (err != 0) {
					(void)fprintf(stderr, "[%s] collect_and_push failed with err: %d\n", col->name, err);
					push_errors++;
				}
			}
		}

		if (verbose) {
			printf("==== tracefox-agent sample @ %u (tlv_errors=%lu) ====\n", timestamp, push_errors);
			for (int i = 0; g_collectors[i] != NULL; i++) {
				struct tf_collector *col = g_collectors[i];
				if (col->print) {
					col->print(col, stdout);
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
			ssize_t sent = sendto(sock, buffer, writer.len, 0, (struct sockaddr *)&dest, sizeof(dest));
			if (sent < 0) {
				push_errors++;
			}
		}
		sleep(cfg.interval_sec);
	}

	if (file_mode) {
		(void)fclose(log_file);
	}
	else {
		close(sock);
	}

	for (int i = 0; g_collectors[i] != NULL; i++) {
		if (g_collectors[i]->destroy) {
			g_collectors[i]->destroy(g_collectors[i]);
		}
	}

	return 0;
}
