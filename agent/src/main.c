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
static const char * default_cfg_path      = "config/agent.conf";

static void handle_signal(int sig)
{
	(void)sig;
	keep_running = 0;
}

static void config_defaults(struct agent_config * cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	strncpy(cfg->server_host, TF_DEFAULT_SERVER_HOST, sizeof(cfg->server_host) - 1);
	cfg->server_port  = TF_DEFAULT_SERVER_PORT;
	cfg->interval_sec = TF_DEFAULT_INTERVAL_SEC;
}

static int resolve_addr(const char * host, uint16_t port, struct sockaddr_in * addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port   = htons(port);

	if (inet_pton(AF_INET, host, &addr->sin_addr) != 1) {
		return -1;
	}

	return 0;
}

static char * trim_inplace(char * string)
{
	char * end = NULL;

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

static void load_config_file(const char * path, struct agent_config * cfg)
{
	FILE * config_fp             = NULL;
	char line[TF_LINE_BUF_SMALL] = {0};
	unsigned int line_no         = 0;

	config_fp = fopen(path, "r");
	if (!config_fp) {
		return;
	}

	while (fgets(line, sizeof(line), config_fp) != NULL) {
		char * key  = NULL;
		char * val  = NULL;
		char * eqs  = NULL;
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
			char * saveptr = NULL;
			char * prefix  = strtok_r(val, ",", &saveptr);

			while (prefix) {
				prefix = trim_inplace(prefix);
				if (*prefix != '\0') {
					proc_add_comm_prefix(prefix);
				}
				prefix = strtok_r(NULL, ",", &saveptr);
			}
		}
	}

	(void)fclose(config_fp);
}

static void config_init_from_sources(int argc, char ** argv, struct agent_config * cfg)
{
	const char * selected_path = default_cfg_path;

	/* 先设置默认值 */
	config_defaults(cfg);

	/*
	 * 这里只做一次“手工”扫描 argv 来寻找 -c 配置文件参数，
	 * 避免使用 getopt 破坏后面真正参数解析的全局状态
	 *（此前的实现会调用 getopt 两次，导致后续 -h/-p/-i 被错位解析）。
	 */
	for (int i = 1; i < argc - 1; ++i) {
		if (strcmp(argv[i], "-c") == 0 && argv[i + 1] != NULL && argv[i + 1][0] != '\0') {
			selected_path = argv[i + 1];
			break;
		}
	}

	load_config_file(selected_path, cfg);
}

int main(int argc, char ** argv)
{
	int opt            = 0;
	int sock           = -1;
	int file_mode      = 0;
	uint32_t seq       = 0;
	char * output_file = NULL;
	FILE * log_file    = NULL;

	uint8_t buffer[TF_FRAME_BUF_SIZE]        = {0};
	struct sockaddr_in dest                  = {0};
	struct agent_config cfg                  = {0};
	struct tlv_writer writer                 = {0};

	/* We must initialize collectors that have config dependencies before parsing config */
	for (int i = 0; g_collectors[i] != NULL; i++) {
		if (g_collectors[i]->init) {
			g_collectors[i]->init(g_collectors[i], &cfg);
		}
	}

	config_init_from_sources(argc, argv, &cfg);

	while ((opt = getopt(argc, argv, "c:h:p:i:f:P:v")) != -1) {
		switch (opt) {
		case 'c':
			/* 配置文件已在初始化阶段读取，命令行第二次解析时仅消费该参数 */
			break;
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
			char * saveptr = NULL;
			char * prefix  = strtok_r(optarg, ",", &saveptr);
			while (prefix) {
				prefix = trim_inplace(prefix);
				if (*prefix != '\0') {
					proc_add_comm_prefix(prefix);
				}
				prefix = strtok_r(NULL, ",", &saveptr);
			}
			break;
		}
		case 'v': verbose = true; break;
		default: (void)fprintf(stderr, "Usage: %s [-c config] [-h host] [-p port] [-i interval] [-f file] [-P proc_prefix1,...] [-v]\n", argv[0]); return 1;
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
		/* 新文件时写入帧头：用 ftell 判断是否为空 */
		(void)fseek(log_file, 0, SEEK_END);
		if (ftell(log_file) == 0) {
			char header[TF_HEADER_LEN] = {'T', 'F', 'O', 'X', TF_HEADER_VER, 0x00, 0x00, 0x00};
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

		unsigned long push_errors = 0;

		for (int i = 0; g_collectors[i] != NULL; i++) {
			struct tf_collector * col = g_collectors[i];
			if (col->collect_and_push) {
				int err = col->collect_and_push(col, &writer, &cfg);
				if (err != 0) {
					(void)fprintf(stderr, "[%s] collect_and_push failed with err: %d\n", col->name, err);
					push_errors++;
				}
			}
		}

		if (verbose) {
			printf("==== tracefox-agent sample @ %u (tlv_errors=%lu) ====\n", timestamp, push_errors);
			for (int i = 0; g_collectors[i] != NULL; i++) {
				struct tf_collector * col = g_collectors[i];
				if (col->print) {
					col->print(col, stdout);
				}
			}
		}

		if (file_mode) {
			/* 帧长 2 字节大端 */
			uint16_t frame_len = (uint16_t)writer.len;
			uint8_t len_bytes[TF_FRAME_LEN_BYTES];
			len_bytes[0] = (uint8_t)((frame_len >> 8) & TF_BYTE_MASK);
			len_bytes[1] = (uint8_t)(frame_len & TF_BYTE_MASK);
			(void)fwrite(len_bytes, 1, TF_FRAME_LEN_BYTES, log_file);
			// Write TLV data
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
