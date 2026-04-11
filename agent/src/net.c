#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tracefox.h"

struct net_ctx
{
	struct net_entry entries[TF_MAX_INTERFACES];
	size_t count;
	int truncated;
};

static int net_init(struct tf_collector *col, const struct agent_config *cfg)
{
	(void)cfg;
	struct net_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -1;
	}
	col->ctx = ctx;
	return 0;
}

static void net_destroy(struct tf_collector *col)
{
	if (col && col->ctx) {
		free(col->ctx);
		col->ctx = NULL;
	}
}

static int net_collect(struct net_ctx *ctx, const struct agent_config *cfg)
{
	(void)cfg;

	size_t idx                   = 0;
	char line[TF_LINE_BUF_NET]   = { 0 };
	char iface[TF_NET_IFACE_BUF] = { 0 };
	unsigned long long rx_bytes  = 0ULL;
	unsigned long long tx_bytes  = 0ULL;
	struct net_entry *entry      = NULL;
	FILE *net_dev_fp             = NULL;

	net_dev_fp = fopen("/proc/net/dev", "r");
	if (!net_dev_fp) {
		ctx->count = 0;
		return -1;
	}

	/* Skip the two header lines in /proc/net/dev */
	if (!fgets(line, sizeof(line), net_dev_fp)) {
		(void)fclose(net_dev_fp);
		ctx->count = 0;
		return -1;
	}

	if (!fgets(line, sizeof(line), net_dev_fp)) {
		(void)fclose(net_dev_fp);
		ctx->count = 0;
		return -1;
	}

	idx = 0;
	while (idx < TF_MAX_INTERFACES && fgets(line, sizeof(line), net_dev_fp)) {
		if (sscanf(line, TF_NET_DEV_SSCANF_FMT, iface, &rx_bytes, &tx_bytes) != 3) { /* NOLINT */
			continue;
		}

		if (strcmp(iface, "lo") == 0) {
			continue;
		}
		entry = &ctx->entries[idx];
		memset(entry, 0, sizeof(*entry));
		strncpy(entry->name, iface, sizeof(entry->name) - 1);
		entry->name[sizeof(entry->name) - 1] = '\0';
		entry->rx_bytes                      = rx_bytes;
		entry->tx_bytes                      = tx_bytes;

		idx++;
	}

	if (idx >= TF_MAX_INTERFACES && fgets(line, sizeof(line), net_dev_fp)) {
		if (!ctx->truncated) {
			TF_LOG_WARN("[net] interface limit (%d) reached, some interfaces dropped", TF_MAX_INTERFACES);
			ctx->truncated = 1;
		}
	}

	(void)fclose(net_dev_fp);

	ctx->count = idx;
	return 0;
}

static int net_push(struct net_ctx *ctx, struct tlv_writer *wrt)
{
	if (ctx->count == 0) {
		return 0; /* Nothing to push */
	}

	uint8_t payload[1 + TF_MAX_INTERFACES * TF_NET_ENTRY_PAYLOAD_LEN] = { 0 };
	uint8_t *payload_cursor                                           = payload;
	size_t idx                                                        = 0;
	char name[TF_NET_NAME_SIZE]                                       = { 0 };
	struct net_entry *entry                                           = NULL;

	*payload_cursor++ = (uint8_t)ctx->count;
	for (idx = 0; idx < ctx->count; ++idx) {
		entry = &ctx->entries[idx];
		memset(name, 0, sizeof(name));
		strncpy(name, entry->name, sizeof(name) - 1);

		memcpy(payload_cursor, name, sizeof(name));
		payload_cursor += sizeof(name);

		buf_put_be_u64(&payload_cursor, entry->rx_bytes);
		buf_put_be_u64(&payload_cursor, entry->tx_bytes);
	}

	return tlv_put(wrt, TF_TYPE_NET, payload, (uint8_t)(payload_cursor - payload));
}

static int net_collect_and_push(struct tf_collector *col, struct tlv_writer *wrt, const struct agent_config *cfg, struct sample_context *sctx)
{
	(void)sctx;
	struct net_ctx *ctx = (struct net_ctx *)col->ctx;
	if (!ctx) return -1;

	if (net_collect(ctx, cfg) != 0) {
		return -1;
	}

	return net_push(ctx, wrt);
}

static void net_print(struct tf_collector *col, FILE *out)
{
	struct net_ctx *ctx = (struct net_ctx *)col->ctx;
	if (!ctx) return;

	(void)fprintf(out, "NET : count=%zu\n", ctx->count);
	for (size_t i = 0; i < ctx->count; i++) {
		(void)fprintf(out, "  - %s: rx_bytes=%llu tx_bytes=%llu\n", ctx->entries[i].name, (unsigned long long)ctx->entries[i].rx_bytes,
		              (unsigned long long)ctx->entries[i].tx_bytes);
	}
}

struct tf_collector net_collector = {
	.name             = "net",
	.ctx              = NULL,
	.init             = net_init,
	.destroy          = net_destroy,
	.collect_and_push = net_collect_and_push,
	.print            = net_print,
};
