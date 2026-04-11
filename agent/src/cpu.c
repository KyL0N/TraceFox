#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tracefox.h"

#define CPU_STAT_FIELDS 7

struct cpu_ctx
{
	unsigned long long prev_total;
	unsigned long long prev_user;
	unsigned long long prev_nice;
	unsigned long long prev_system;
	unsigned long long prev_idle;
	unsigned long long prev_iowait;
	unsigned long long prev_irq;
	unsigned long long prev_softirq;
	int initialized;
	struct cpu_payload last_payload;
};

static unsigned long long g_last_diff_total = 1;

static int cpu_init(struct tf_collector *col, const struct agent_config *cfg)
{
	(void)cfg;
	struct cpu_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -1;
	}
	col->ctx = ctx;
	return 0;
}

static void cpu_destroy(struct tf_collector *col)
{
	if (col && col->ctx) {
		free(col->ctx);
		col->ctx = NULL;
	}
}

static int cpu_collect(struct cpu_ctx *ctx, const struct agent_config *cfg)
{
	(void)cfg;
	FILE *stat_fp = fopen("/proc/stat", "r");
	if (!stat_fp) {
		memset(&ctx->last_payload, 0, sizeof(ctx->last_payload));
		return -1;
	}

	char line[TF_LINE_BUF_SMALL];
	if (!fgets(line, sizeof(line), stat_fp)) {
		(void)fclose(stat_fp);
		memset(&ctx->last_payload, 0, sizeof(ctx->last_payload));
		return -1;
	}
	(void)fclose(stat_fp);

	unsigned long long user    = 0;
	unsigned long long nicev   = 0;
	unsigned long long system  = 0;
	unsigned long long idle    = 0;
	unsigned long long iowait  = 0;
	unsigned long long irq     = 0;
	unsigned long long softirq = 0;

	int ret = sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu", &user, &nicev, &system, &idle, &iowait, &irq, &softirq); // NOLINT
	if (ret != CPU_STAT_FIELDS) {
		memset(&ctx->last_payload, 0, sizeof(ctx->last_payload));
		return -1;
	}

	unsigned long long total = user + nicev + system + idle + iowait + irq + softirq;

	if (!ctx->initialized) {
		ctx->prev_total   = total;
		ctx->prev_user    = user;
		ctx->prev_nice    = nicev;
		ctx->prev_system  = system;
		ctx->prev_idle    = idle;
		ctx->prev_iowait  = iowait;
		ctx->prev_irq     = irq;
		ctx->prev_softirq = softirq;
		ctx->initialized  = 1;
		memset(&ctx->last_payload, 0, sizeof(ctx->last_payload));
		g_last_diff_total = 1;
		return 0;
	}

	unsigned long long diff_total = total - ctx->prev_total;
	if (diff_total == 0) {
		diff_total = 1;
	}
	g_last_diff_total = diff_total;

	unsigned long long diff_user   = (user - ctx->prev_user) + (nicev - ctx->prev_nice);
	unsigned long long diff_system = system - ctx->prev_system;
	unsigned long long diff_idle   = idle - ctx->prev_idle;
	unsigned long long diff_iowait = iowait - ctx->prev_iowait;
	unsigned long long diff_irq    = (irq - ctx->prev_irq) + (softirq - ctx->prev_softirq);

	ctx->prev_total   = total;
	ctx->prev_user    = user;
	ctx->prev_nice    = nicev;
	ctx->prev_system  = system;
	ctx->prev_idle    = idle;
	ctx->prev_iowait  = iowait;
	ctx->prev_irq     = irq;
	ctx->prev_softirq = softirq;

	ctx->last_payload.user   = (uint16_t)((diff_user * (unsigned long long)TF_CPU_PERCENT_SCALE) / diff_total);
	ctx->last_payload.system = (uint16_t)((diff_system * (unsigned long long)TF_CPU_PERCENT_SCALE) / diff_total);
	ctx->last_payload.idle   = (uint16_t)((diff_idle * (unsigned long long)TF_CPU_PERCENT_SCALE) / diff_total);
	ctx->last_payload.iowait = (uint16_t)((diff_iowait * (unsigned long long)TF_CPU_PERCENT_SCALE) / diff_total);
	ctx->last_payload.irq    = (uint16_t)((diff_irq * (unsigned long long)TF_CPU_PERCENT_SCALE) / diff_total);
	return 0;
}

static int cpu_push(struct cpu_ctx *ctx, struct tlv_writer *wrt)
{
	uint8_t payload[TF_CPU_PAYLOAD_LEN] = { 0 };
	uint8_t *payload_cursor             = payload;

	*payload_cursor++ = (uint8_t)(ctx->last_payload.user >> 8);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.user & TF_BYTE_MASK);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.system >> 8);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.system & TF_BYTE_MASK);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.idle >> 8);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.idle & TF_BYTE_MASK);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.iowait >> 8);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.iowait & TF_BYTE_MASK);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.irq >> 8);
	*payload_cursor++ = (uint8_t)(ctx->last_payload.irq & TF_BYTE_MASK);

	return tlv_put(wrt, TF_TYPE_CPU, payload, (uint8_t)(payload_cursor - payload));
}

static int cpu_collect_and_push(struct tf_collector *col, struct tlv_writer *wrt, const struct agent_config *cfg, struct sample_context *sctx)
{
	struct cpu_ctx *ctx = (struct cpu_ctx *)col->ctx;
	if (!ctx) return -1;

	if (cpu_collect(ctx, cfg) != 0) {
		return -1;
	}

	if (sctx) {
		sctx->cpu_total_diff = g_last_diff_total ? g_last_diff_total : 1;
	}

	return cpu_push(ctx, wrt);
}

static void cpu_print(struct tf_collector *col, FILE *out)
{
	struct cpu_ctx *ctx = (struct cpu_ctx *)col->ctx;
	if (!ctx) return;

	(void)fprintf(out, "CPU : user=%3u.%1u%% sys=%3u.%1u%% idle=%3u.%1u%% iowait=%3u.%1u%% irq=%3u.%1u%%\n",
	              (unsigned)(ctx->last_payload.user / TF_PERCENT_DIV), (unsigned)(ctx->last_payload.user % TF_PERCENT_DIV),
	              (unsigned)(ctx->last_payload.system / TF_PERCENT_DIV), (unsigned)(ctx->last_payload.system % TF_PERCENT_DIV),
	              (unsigned)(ctx->last_payload.idle / TF_PERCENT_DIV), (unsigned)(ctx->last_payload.idle % TF_PERCENT_DIV),
	              (unsigned)(ctx->last_payload.iowait / TF_PERCENT_DIV), (unsigned)(ctx->last_payload.iowait % TF_PERCENT_DIV),
	              (unsigned)(ctx->last_payload.irq / TF_PERCENT_DIV), (unsigned)(ctx->last_payload.irq % TF_PERCENT_DIV));
}

struct tf_collector cpu_collector = {
	.name             = "cpu",
	.ctx              = NULL,
	.init             = cpu_init,
	.destroy          = cpu_destroy,
	.collect_and_push = cpu_collect_and_push,
	.print            = cpu_print,
};
