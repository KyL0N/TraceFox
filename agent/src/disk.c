#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "tracefox.h"

struct disk_cache
{
	char name[TF_DISK_CACHE_NAME_LEN];
	unsigned long long reads;
	unsigned long long writes;
	unsigned long long sectors_read;
	unsigned long long sectors_written;
	unsigned long long read_ms;
	unsigned long long write_ms;
	unsigned long long io_ticks;
};

struct disk_ctx
{
	struct disk_cache cache[TF_MAX_DISKS];
	struct disk_entry entries[TF_MAX_DISKS];
	size_t count;
};

static int is_partition_name(const char * name)
{
	if (!name) {
		return 0;
	}

	size_t len = strlen(name);
	if (len == 0) {
		return 0;
	}

	if (strncmp(name, "loop", 4) == 0 || strncmp(name, "ram", 3) == 0 || strncmp(name, "dm-", 3) == 0) {
		return 1;
	}

	if (strncmp(name, "nvme", 4) == 0) {
		return strchr(name, 'p') != NULL;
	}

	if (strncmp(name, "mmcblk", 6) == 0) {
		return strchr(name, 'p') != NULL;
	}

	return isdigit((unsigned char)name[len - 1]);
}

static struct disk_cache * disk_cache_slot(struct disk_ctx * ctx, const char * name)
{
	if (!name) {
		return NULL;
	}

	for (size_t i = 0; i < TF_MAX_DISKS; ++i) {
		if (strcmp(ctx->cache[i].name, name) == 0) {
			return &ctx->cache[i];
		}
	}

	for (size_t i = 0; i < TF_MAX_DISKS; ++i) {
		if (ctx->cache[i].name[0] == '\0') {
			strncpy(ctx->cache[i].name, name, sizeof(ctx->cache[i].name) - 1);
			return &ctx->cache[i];
		}
	}

	return NULL;
}

static int disk_init(struct tf_collector * col, const struct agent_config * cfg)
{
	(void)cfg;
	struct disk_ctx * ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -1;
	}
	col->ctx = ctx;
	return 0;
}

static void disk_destroy(struct tf_collector * col)
{
	if (col && col->ctx) {
		free(col->ctx);
		col->ctx = NULL;
	}
}

static int disk_collect(struct disk_ctx * ctx, const struct agent_config * cfg)
{
	uint16_t interval_sec = cfg->interval_sec;
	if (interval_sec == 0) {
		interval_sec = 1;
	}

	FILE * disk_fp = fopen("/proc/diskstats", "r");
	if (!disk_fp) {
		ctx->count = 0;
		return -1;
	}

	char line[TF_LINE_BUF_SMALL];
	size_t idx = 0;

	while (idx < TF_MAX_DISKS && fgets(line, sizeof(line), disk_fp)) {
		char name[TF_DISK_NAME_BUF] = { 0 };
		unsigned int major          = 0;
		unsigned int minor          = 0;
		unsigned long long rd_comp  = 0;
		unsigned long long rd_merg  = 0;
		unsigned long long rd_sect  = 0;
		unsigned long long rd_ticks = 0;

		unsigned long long wr_comp  = 0;
		unsigned long long wr_merg  = 0;
		unsigned long long wr_sect  = 0;
		unsigned long long wr_ticks = 0;

		unsigned long long ios           = 0;
		unsigned long long io_ticks      = 0;
		unsigned long long time_in_queue = 0;

		int parsed = sscanf(line, TF_DISK_SSCANF_FMT, &major, &minor, name, &rd_comp, &rd_merg, &rd_sect, // NOLINT
		                    &rd_ticks, &wr_comp, &wr_merg, &wr_sect, &wr_ticks, &ios, &io_ticks, &time_in_queue);
		if (parsed < TF_DISK_STAT_MIN) {
			continue;
		}

		if (is_partition_name(name)) {
			continue;
		}

		struct disk_cache * slot = disk_cache_slot(ctx, name);
		if (!slot) {
			continue;
		}

		struct disk_entry * entry = &ctx->entries[idx];
		memset(entry, 0, sizeof(*entry));
		strncpy(entry->name, name, sizeof(entry->name) - 1);

		int have_prev = (slot->reads != 0 || slot->writes != 0 || slot->sectors_read != 0 || slot->sectors_written != 0 || slot->io_ticks != 0);

		unsigned long long diff_reads    = rd_comp - slot->reads;
		unsigned long long diff_writes   = wr_comp - slot->writes;
		unsigned long long diff_io_ticks = io_ticks - slot->io_ticks;

		/* 累积计数直接抛给 server，方便做长期趋势 */
		entry->reads_completed  = (uint32_t)rd_comp;
		entry->writes_completed = (uint32_t)wr_comp;
		entry->sectors_read     = (uint32_t)rd_sect;
		entry->sectors_written  = (uint32_t)wr_sect;
		entry->read_ms          = (uint32_t)rd_ticks;
		entry->write_ms         = (uint32_t)wr_ticks;

		/* 更新缓存 */
		slot->reads           = rd_comp;
		slot->writes          = wr_comp;
		slot->sectors_read    = rd_sect;
		slot->sectors_written = wr_sect;
		slot->read_ms         = rd_ticks;
		slot->write_ms        = wr_ticks;
		slot->io_ticks        = io_ticks;

		/* per-interval envelope：IOPS + util% */
		entry->read_iops_delta  = 0;
		entry->write_iops_delta = 0;
		entry->io_util_pct_x10  = 0;

		if (have_prev) {
			entry->read_iops_delta  = (uint32_t)(diff_reads > 0 ? diff_reads : 0);
			entry->write_iops_delta = (uint32_t)(diff_writes > 0 ? diff_writes : 0);

			if (diff_io_ticks > 0) {
				/* io_ticks 是毫秒；util_x10 = busy_ms / interval_sec，最大 100.0% → TF_PCT10_MAX */
				unsigned long long pct10 = diff_io_ticks / (unsigned long long)interval_sec;

				if (pct10 > (unsigned long long)TF_PCT10_MAX) {
					pct10 = (unsigned long long)TF_PCT10_MAX;
				}

				entry->io_util_pct_x10 = (uint16_t)pct10;
			}
		}

		idx++;
	}

	(void)fclose(disk_fp);
	ctx->count = idx;
	return 0;
}

static int disk_push(struct disk_ctx * ctx, struct tlv_writer * wrt)
{
	if (ctx->count == 0) {
		return 0;
	}

	uint8_t payload[1 + TF_MAX_DISKS * TF_DISK_ENTRY_PAYLOAD_LEN] = { 0 };
	uint8_t * payload_cursor                                      = payload;
	size_t idx                                                    = 0;
	struct disk_entry * entry                                     = NULL;
	char name[TF_DISK_NAME_SIZE]                                  = { 0 };
	uint32_t vals[TF_DISK_STAT_MIN]                               = { 0 };

	*payload_cursor++ = (uint8_t)ctx->count;
	for (idx = 0; idx < ctx->count; ++idx) {
		entry = &ctx->entries[idx];
		memset(name, 0, sizeof(name));
		memset(vals, 0, sizeof(vals));

		strncpy(name, entry->name, sizeof(name) - 1);

		memcpy(payload_cursor, name, sizeof(name));
		payload_cursor += sizeof(name);

		vals[0] = entry->reads_completed;
		vals[1] = entry->writes_completed;
		vals[2] = entry->sectors_read;
		vals[3] = entry->sectors_written;
		vals[4] = entry->read_ms;
		vals[5] = entry->write_ms;
		vals[6] = entry->read_iops_delta;
		vals[7] = entry->write_iops_delta;

		for (size_t val_idx = 0; val_idx < 8; ++val_idx) {
			*payload_cursor++ = (uint8_t)((vals[val_idx] >> 24) & TF_BYTE_MASK);
			*payload_cursor++ = (uint8_t)((vals[val_idx] >> 16) & TF_BYTE_MASK);
			*payload_cursor++ = (uint8_t)((vals[val_idx] >> 8) & TF_BYTE_MASK);
			*payload_cursor++ = (uint8_t)(vals[val_idx] & TF_BYTE_MASK);
		}

		/* io_util_pct_x10 作为 2 字节追加 */
		*payload_cursor++ = (uint8_t)((entry->io_util_pct_x10 >> 8) & TF_BYTE_MASK);
		*payload_cursor++ = (uint8_t)(entry->io_util_pct_x10 & TF_BYTE_MASK);
	}

	return tlv_put(wrt, TF_TYPE_DISK, payload, (uint8_t)(payload_cursor - payload));
}

static int disk_collect_and_push(struct tf_collector * col, struct tlv_writer * wrt, const struct agent_config * cfg, struct sample_context * sctx)
{
	(void)sctx;
	struct disk_ctx * ctx = (struct disk_ctx *)col->ctx;
	if (!ctx) return -1;

	if (disk_collect(ctx, cfg) != 0) {
		return -1;
	}

	return disk_push(ctx, wrt);
}

static void disk_print(struct tf_collector * col, FILE * out)
{
	struct disk_ctx * ctx = (struct disk_ctx *)col->ctx;
	if (!ctx) return;

	(void)fprintf(out, "DISK: count=%zu\n", ctx->count);
	for (size_t i = 0; i < ctx->count; i++) {
		(void)fprintf(out,
		              "  - %s: cum(r=%u,w=%u,sr=%u,sw=%u,rm=%u,wm=%u) "
		              "delta(iops_r=%u,iops_w=%u) util=%u.%1u%%%%\n",
		              ctx->entries[i].name, ctx->entries[i].reads_completed, ctx->entries[i].writes_completed, ctx->entries[i].sectors_read,
		              ctx->entries[i].sectors_written, ctx->entries[i].read_ms, ctx->entries[i].write_ms, ctx->entries[i].read_iops_delta,
		              ctx->entries[i].write_iops_delta, ctx->entries[i].io_util_pct_x10 / TF_PERCENT_DIV, ctx->entries[i].io_util_pct_x10 % TF_PERCENT_DIV);
	}
}

struct tf_collector disk_collector = {
	.name             = "disk",
	.ctx              = NULL,
	.init             = disk_init,
	.destroy          = disk_destroy,
	.collect_and_push = disk_collect_and_push,
	.print            = disk_print,
};
