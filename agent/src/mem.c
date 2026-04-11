#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tracefox.h"

struct mem_ctx
{
	struct mem_payload last_mem;
	struct load_payload last_load;
};

static int mem_init(struct tf_collector *col, const struct agent_config *cfg)
{
	(void)cfg;
	struct mem_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -1;
	}
	col->ctx = ctx;
	return 0;
}

static void mem_destroy(struct tf_collector *col)
{
	if (col && col->ctx) {
		free(col->ctx);
		col->ctx = NULL;
	}
}

static int mem_collect(struct mem_ctx *ctx, const struct agent_config *cfg)
{
	(void)cfg;

	FILE *meminfo_fp = fopen("/proc/meminfo", "r");
	if (!meminfo_fp) {
		memset(&ctx->last_mem, 0, sizeof(ctx->last_mem));
		return -1;
	}

	char key[TF_KEY_BUF] = { 0 };
	unsigned long value  = 0UL;
	unsigned long total  = 0UL;
	unsigned long freev  = 0UL;
	unsigned long avail  = 0UL;

	while (fscanf(meminfo_fp, TF_FSCANF_MEMINFO_FMT, key, &value) == 2) { // NOLINT
		if (strcmp(key, "MemTotal:") == 0) {
			total = value;
		}
		else if (strcmp(key, "MemFree:") == 0) {
			freev = value;
		}
		else if (strcmp(key, "MemAvailable:") == 0) {
			avail = value;
		}

		// If we have all the values we need, break out of the loop
		if (total && freev && avail) {
			break;
		}

		// Skip the rest of the line
		int ch_idx;
		while ((ch_idx = fgetc(meminfo_fp)) != '\n' && ch_idx != EOF) {
		}
	}
	(void)fclose(meminfo_fp);

	ctx->last_mem.mem_total_kb     = (uint32_t)total;
	ctx->last_mem.mem_free_kb      = (uint32_t)freev;
	ctx->last_mem.mem_available_kb = (uint32_t)avail;

	FILE *lfp = fopen("/proc/loadavg", "r");
	if (!lfp) {
		memset(&ctx->last_load, 0, sizeof(ctx->last_load));
		return -1;
	}

	double load1  = 0.0;
	double load5  = 0.0;
	double load15 = 0.0;
	if (fscanf(lfp, "%lf %lf %lf", &load1, &load5, &load15) != 3) { // NOLINT
		load1 = load5 = load15 = 0.0;
	}
	(void)fclose(lfp);

	ctx->last_load.load1_x100  = (uint16_t)(load1 * (double)TF_LOAD_SCALE);
	ctx->last_load.load5_x100  = (uint16_t)(load5 * (double)TF_LOAD_SCALE);
	ctx->last_load.load15_x100 = (uint16_t)(load15 * (double)TF_LOAD_SCALE);

	return 0;
}

static int mem_push(struct mem_ctx *ctx, struct tlv_writer *wrt)
{
	uint8_t payload[TF_MEM_PAYLOAD_LEN] = { 0 };
	uint8_t *payload_cursor             = payload;

	buf_put_be_u32(&payload_cursor, ctx->last_mem.mem_total_kb);
	buf_put_be_u32(&payload_cursor, ctx->last_mem.mem_free_kb);
	buf_put_be_u32(&payload_cursor, ctx->last_mem.mem_available_kb);
	buf_put_be_u16(&payload_cursor, ctx->last_load.load1_x100);
	buf_put_be_u16(&payload_cursor, ctx->last_load.load5_x100);
	buf_put_be_u16(&payload_cursor, ctx->last_load.load15_x100);

	return tlv_put(wrt, TF_TYPE_MEM, payload, (uint8_t)(payload_cursor - payload));
}

static int mem_collect_and_push(struct tf_collector *col, struct tlv_writer *wrt, const struct agent_config *cfg, struct sample_context *sctx)
{
	(void)sctx;
	struct mem_ctx *ctx = (struct mem_ctx *)col->ctx;
	if (!ctx) return -1;

	if (mem_collect(ctx, cfg) != 0) {
		return -1;
	}

	return mem_push(ctx, wrt);
}

static void mem_print(struct tf_collector *col, FILE *out)
{
	struct mem_ctx *ctx = (struct mem_ctx *)col->ctx;
	if (!ctx) return;

	uint32_t mem_used = ctx->last_mem.mem_total_kb > ctx->last_mem.mem_available_kb ? (ctx->last_mem.mem_total_kb - ctx->last_mem.mem_available_kb) : 0;

	(void)fprintf(out, "MEM : total=%u kB free=%u kB avail=%u kB used=%u kB\n", ctx->last_mem.mem_total_kb, ctx->last_mem.mem_free_kb,
	              ctx->last_mem.mem_available_kb, mem_used);

	(void)fprintf(out, "LOAD: 1m=%u.%02u 5m=%u.%02u 15m=%u.%02u\n", (unsigned)(ctx->last_load.load1_x100 / TF_LOAD_SCALE),
	              (unsigned)(ctx->last_load.load1_x100 % TF_LOAD_SCALE), (unsigned)(ctx->last_load.load5_x100 / TF_LOAD_SCALE),
	              (unsigned)(ctx->last_load.load5_x100 % TF_LOAD_SCALE), (unsigned)(ctx->last_load.load15_x100 / TF_LOAD_SCALE),
	              (unsigned)(ctx->last_load.load15_x100 % TF_LOAD_SCALE));
}

struct tf_collector mem_collector = {
	.name             = "mem",
	.ctx              = NULL,
	.init             = mem_init,
	.destroy          = mem_destroy,
	.collect_and_push = mem_collect_and_push,
	.print            = mem_print,
};
