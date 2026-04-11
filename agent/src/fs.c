#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include "tracefox.h"

struct fs_ctx
{
	struct fs_entry entries[TF_MAX_FS];
	size_t count;
};

static const char * const fs_whitelist[] = { "ext4", "ext3", "ext2", "f2fs", "btrfs", "xfs", "vfat", "ntfs", "exfat", NULL };

static int fs_type_allowed(const char * type)
{
	for (size_t i = 0; fs_whitelist[i]; ++i) {
		if (strcmp(type, fs_whitelist[i]) == 0) {
			return 1;
		}
	}

	return 0;
}

static int fs_init(struct tf_collector * col, const struct agent_config * cfg)
{
	(void)cfg;
	struct fs_ctx * ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -1;
	}
	col->ctx = ctx;
	return 0;
}

static void fs_destroy(struct tf_collector * col)
{
	if (col && col->ctx) {
		free(col->ctx);
		col->ctx = NULL;
	}
}

static int fs_collect(struct fs_ctx * ctx, const struct agent_config * cfg)
{
	(void)cfg;

	FILE * mounts_fp = fopen("/proc/mounts", "r");
	if (!mounts_fp) {
		ctx->count = 0;
		return -1;
	}

	size_t idx                  = 0;
	char dev[TF_FS_DEV_BUF]     = { 0 };
	char mount[TF_FS_MOUNT_BUF] = { 0 };
	char type[TF_FS_TYPE_BUF]   = { 0 };
	char opts[TF_FS_OPTS_BUF]   = { 0 };
	int freq                    = 0;
	int passno                  = 0;

	while (idx < TF_MAX_FS && fscanf(mounts_fp, TF_FSCANF_MOUNTS_FMT, dev, mount, type, opts, &freq, &passno) == 6) { // NOLINT
		if (!fs_type_allowed(type)) {
			continue;
		}

		struct statvfs svfs;
		if (statvfs(mount, &svfs) != 0) {
			continue;
		}

		struct fs_entry * entry = &ctx->entries[idx++];
		memset(entry, 0, sizeof(*entry));
		strncpy(entry->mount, mount, sizeof(entry->mount) - 1);
		entry->mount[sizeof(entry->mount) - 1] = '\0';

		uint64_t total  = (uint64_t)svfs.f_blocks * svfs.f_frsize / (uint64_t)TF_KB;
		uint64_t freeb  = (uint64_t)svfs.f_bfree * svfs.f_frsize / (uint64_t)TF_KB;
		entry->total_kb = (uint32_t)total;

		if (total == 0) {
			entry->used_pct_x10 = 0;
		}
		else {
			uint64_t used  = total > freeb ? (total - freeb) : 0;
			uint64_t pct10 = (used * (uint64_t)TF_PCT10_MAX) / total; /* 0.1% 精度 */
			if (pct10 > (uint64_t)TF_PCT10_MAX) {
				pct10 = (uint64_t)TF_PCT10_MAX;
			}
			entry->used_pct_x10 = (uint16_t)pct10;
		}
	}

	(void)fclose(mounts_fp);
	ctx->count = idx;
	return 0;
}

static int fs_push(struct fs_ctx * ctx, struct tlv_writer * wrt)
{
	if (ctx->count == 0) {
		return 0;
	}

	uint8_t payload[1 + TF_MAX_FS * TF_FS_ENTRY_PAYLOAD_LEN] = { 0 };
	uint8_t * payload_cursor                                 = payload;
	char name[TF_FS_MOUNT_SIZE]                              = { 0 };
	struct fs_entry * entry                                  = NULL;

	*payload_cursor++ = (uint8_t)ctx->count;
	for (size_t entry_idx = 0; entry_idx < ctx->count; ++entry_idx) {
		entry = &ctx->entries[entry_idx];

		memset(name, 0, sizeof(name));
		strncpy(name, entry->mount, sizeof(name) - 1);

		memcpy(payload_cursor, name, sizeof(name));
		payload_cursor += sizeof(name);
		*payload_cursor++ = (uint8_t)(entry->total_kb >> 24);
		*payload_cursor++ = (uint8_t)(entry->total_kb >> 16);
		*payload_cursor++ = (uint8_t)(entry->total_kb >> 8);
		*payload_cursor++ = (uint8_t)entry->total_kb;
		*payload_cursor++ = (uint8_t)(entry->used_pct_x10 >> 8);
		*payload_cursor++ = (uint8_t)(entry->used_pct_x10 & TF_BYTE_MASK);
	}

	return tlv_put(wrt, TF_TYPE_FS, payload, (uint8_t)(payload_cursor - payload));
}

static int fs_collect_and_push(struct tf_collector * col, struct tlv_writer * wrt, const struct agent_config * cfg)
{
	struct fs_ctx * ctx = (struct fs_ctx *)col->ctx;
	if (!ctx) return -1;

	if (fs_collect(ctx, cfg) != 0) {
		return -1;
	}

	return fs_push(ctx, wrt);
}

static void fs_print(struct tf_collector * col, FILE * out)
{
	struct fs_ctx * ctx = (struct fs_ctx *)col->ctx;
	if (!ctx) return;

	(void)fprintf(out, "FS  : count=%zu\n", ctx->count);
	for (size_t i = 0; i < ctx->count; i++) {
		(void)fprintf(out, "  - %s: total=%u kB used=%u.%1u%%%%\n", ctx->entries[i].mount, ctx->entries[i].total_kb,
		              ctx->entries[i].used_pct_x10 / TF_PERCENT_DIV, ctx->entries[i].used_pct_x10 % TF_PERCENT_DIV);
	}
}

struct tf_collector fs_collector = {
	.name             = "fs",
	.ctx              = NULL,
	.init             = fs_init,
	.destroy          = fs_destroy,
	.collect_and_push = fs_collect_and_push,
	.print            = fs_print,
};
