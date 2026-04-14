#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include "tracefox.h"

#define MAX_COMM_PREFIX 32 // 最多支持 32 个前缀
#define COMM_PREFIX_LEN 32 // 每个前缀最长 31 字节
#define PID_HASH(pid)   ((unsigned long)((unsigned int)(pid) * 2654435761u) % TF_PROC_TRACK)

struct pid_list
{
	long pids[TF_PROC_TRACK];
	size_t count;
};

struct watch_group
{
	char name[COMM_PREFIX_LEN];
	struct pid_list list;
};

struct proc_prev
{
	long pid;
	unsigned long long ticks;
};

struct proc_ctx
{
	struct proc_prev history[TF_PROC_TRACK];
	char comm_prefix_list[MAX_COMM_PREFIX][COMM_PREFIX_LEN];
	struct watch_group watch_groups[MAX_COMM_PREFIX];
	int disabled;
	size_t cpu_count;
	size_t comm_prefix_count;
	size_t watch_group_count;
	time_t last_scan_time;
	unsigned long long cpu_total_diff;
	struct proc_payload last_payload;
};

static void apply_config_prefixes(struct proc_ctx *ctx, const struct agent_config *cfg)
{
	for (size_t i = 0; i < cfg->proc_prefix_count && i < MAX_COMM_PREFIX; ++i) {
		strncpy(ctx->comm_prefix_list[i], cfg->proc_prefixes[i], COMM_PREFIX_LEN - 1);
		ctx->comm_prefix_list[i][COMM_PREFIX_LEN - 1] = '\0';

		strncpy(ctx->watch_groups[i].name, cfg->proc_prefixes[i], COMM_PREFIX_LEN - 1);
		ctx->watch_groups[i].name[COMM_PREFIX_LEN - 1] = '\0';
		ctx->watch_groups[i].list.count                = 0;
	}
	ctx->comm_prefix_count = cfg->proc_prefix_count;
	ctx->watch_group_count = cfg->proc_prefix_count;
}

static int comm_prefix_match(struct proc_ctx *ctx, const char *comm)
{
	if (ctx->comm_prefix_count == 0) {
		return 1; // 没设置前缀 → 全部监控
	}
	for (size_t i = 0; i < ctx->comm_prefix_count; i++) {
		const char *prefix = ctx->comm_prefix_list[i];
		if (strncmp(comm, prefix, strlen(prefix)) == 0) {
			return 1;
		}
	}
	return 0;
}

static struct proc_prev *find_slot(struct proc_ctx *ctx, long pid)
{
	size_t idx = PID_HASH(pid);

	if (ctx->history[idx].pid == pid) {
		return &ctx->history[idx];
	}

	if (ctx->history[idx].pid == 0) {
		ctx->history[idx].pid   = pid;
		ctx->history[idx].ticks = 0;
		return &ctx->history[idx];
	}

	// 线性探测（避免冲突）
	for (size_t i = 0; i < TF_PROC_TRACK; i++) {
		if (ctx->history[i].pid == pid) {
			return &ctx->history[i];
		}

		if (ctx->history[i].pid == 0) {
			ctx->history[i].pid   = pid;
			ctx->history[i].ticks = 0;
			return &ctx->history[i];
		}
	}

	// 最坏情况：覆盖哈希位
	return &ctx->history[idx];
}

static size_t get_cpu_count(struct proc_ctx *ctx)
{
	if (ctx->cpu_count <= 0) {
		ctx->cpu_count = (size_t)sysconf(_SC_NPROCESSORS_ONLN);
		if (ctx->cpu_count <= 0) {
			ctx->cpu_count = 1;
		}
	}

	return ctx->cpu_count;
}

static unsigned long long parse_stat(const char *path, int *pid_out, char *comm_out)
{
	FILE *stat_fp = fopen(path, "r");
	if (!stat_fp) {
		return 0;
	}

	char buf[512];
	if (!fgets(buf, (int)sizeof(buf), stat_fp)) {
		(void)fclose(stat_fp);
		return 0;
	}
	(void)fclose(stat_fp);

	int pid;
	if (sscanf(buf, "%d ", &pid) != 1) { // NOLINT
		return 0;
	}
	*pid_out = pid;

	char *left  = strchr(buf, '(');
	char *right = strrchr(buf, ')');
	if (!left || !right || right <= left) {
		return 0;
	}

	size_t comm_len = (size_t)(right - left - 1);
	if (comm_len > TF_PROC_COMM_MAX) {
		comm_len = TF_PROC_COMM_MAX;
	}

	strncpy(comm_out, left + 1, comm_len);
	comm_out[comm_len] = '\0';

	unsigned long long utime = 0ULL;
	unsigned long long stime = 0ULL;
	char *link               = right + 1;

	if (sscanf(link, " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu", &utime, &stime) != 2) { // NOLINT
		return 0;
	}

	return utime + stime;
}

static uint32_t parse_rss_kb(long pid)
{
	char path[TF_PATH_BUF];
	FILE *status_fp = NULL;

	(void)snprintf(path, sizeof(path), "/proc/%ld/status", pid);
	status_fp = fopen(path, "r");
	if (status_fp) {
		unsigned long value    = 0UL;
		char key[TF_KEY_BUF]   = { 0 };
		char unit[TF_UNIT_BUF] = { 0 };

		while (fscanf(status_fp, TF_FSCANF_STATUS_FMT, key, &value, unit) == 3) { // NOLINT
			if (strcmp(key, "VmRSS:") == 0) {
				(void)fclose(status_fp);
				status_fp = NULL;
				if (value > 0) {
					return (uint32_t)value;
				}
				break;
			}

			int ch_idx = 0;
			while ((ch_idx = fgetc(status_fp)) != '\n' && ch_idx != EOF) {
			}
		}

		if (status_fp) {
			(void)fclose(status_fp);
		}
	}

	(void)snprintf(path, sizeof(path), "/proc/%ld/statm", pid);
	status_fp = fopen(path, "r");
	if (!status_fp) {
		return 0;
	}

	unsigned long total_pages = 0UL;
	unsigned long rss_pages   = 0UL;
	int ret                   = fscanf(status_fp, "%lu %lu", &total_pages, &rss_pages); // NOLINT
	(void)fclose(status_fp);

	if (ret != 2) {
		return 0;
	}

	long page_kb = sysconf(_SC_PAGESIZE) / (long)TF_KB;
	return (uint32_t)(rss_pages * (unsigned long)page_kb);
}

static void history_gc(struct proc_ctx *ctx)
{
	for (size_t i = 0; i < TF_PROC_TRACK; ++i) {
		if (ctx->history[i].pid == 0) {
			continue;
		}
		int alive = 0;
		for (size_t group_idx = 0; group_idx < ctx->watch_group_count && !alive; ++group_idx) {
			for (size_t pid_idx = 0; pid_idx < ctx->watch_groups[group_idx].list.count; ++pid_idx) {
				if (ctx->watch_groups[group_idx].list.pids[pid_idx] == ctx->history[i].pid) {
					alive = 1;
					break;
				}
			}
		}
		if (!alive) {
			ctx->history[i].pid   = 0;
			ctx->history[i].ticks = 0;
		}
	}
}

static void tracker_reset_lists(struct proc_ctx *ctx)
{
	for (size_t i = 0; i < ctx->watch_group_count; ++i) {
		ctx->watch_groups[i].list.count = 0;
	}
}

static void tracker_add_pid(struct proc_ctx *ctx, const char *comm, long pid)
{
	for (size_t i = 0; i < ctx->watch_group_count; ++i) {
		size_t prefix_len = strlen(ctx->watch_groups[i].name);
		if (strncmp(comm, ctx->watch_groups[i].name, prefix_len) == 0) {
			struct pid_list *lst = &ctx->watch_groups[i].list;
			if (lst->count < TF_PROC_TRACK) {
				lst->pids[lst->count++] = pid;
			}
			else {
				TF_LOG_WARN("[proc] PID limit (%d) for group \"%s\", dropping pid %ld", TF_PROC_TRACK, ctx->watch_groups[i].name, pid);
			}
			return;
		}
	}

	if (ctx->comm_prefix_count == 0) {
		if (ctx->watch_group_count < MAX_COMM_PREFIX) {
			size_t g = ctx->watch_group_count;
			strncpy(ctx->watch_groups[g].name, comm, COMM_PREFIX_LEN - 1);
			ctx->watch_groups[g].name[COMM_PREFIX_LEN - 1] = '\0';
			ctx->watch_groups[g].list.pids[0]              = pid;
			ctx->watch_groups[g].list.count                = 1;
			ctx->watch_group_count++;
		}
		else {
			TF_LOG_WARN("[proc] auto-group limit (%d) reached, dropping: %s", MAX_COMM_PREFIX, comm);
		}
	}
}

static void tracker_scan_proc(struct proc_ctx *ctx)
{
	DIR *dir = opendir("/proc");
	if (!dir) {
		return;
	}

	tracker_reset_lists(ctx);

	struct dirent *entry = NULL;
	while ((entry = readdir(dir))) {
		if (!isdigit((unsigned char)entry->d_name[0])) {
			continue;
		}

		long pid = strtol(entry->d_name, NULL, 10);
		if (pid <= 0) {
			continue;
		}

		char comm_path[TF_PATH_BUF] = { 0 };
		(void)snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);

		FILE *comm_fp = fopen(comm_path, "r");
		if (!comm_fp) {
			continue;
		}

		char comm[COMM_PREFIX_LEN];
		if (!fgets(comm, sizeof(comm), comm_fp)) {
			(void)fclose(comm_fp);
			continue;
		}
		(void)fclose(comm_fp);

		size_t len = strlen(comm);
		if (len > 0 && comm[len - 1] == '\n') {
			comm[len - 1] = '\0';
		}

		if (!comm_prefix_match(ctx, comm)) {
			continue;
		}

		tracker_add_pid(ctx, comm, pid);
	}

	closedir(dir);
	history_gc(ctx);
	ctx->last_scan_time = time(NULL);
}

static int proc_init(struct tf_collector *col, const struct agent_config *cfg)
{
	struct proc_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -1;
	}
	col->ctx = ctx;

	apply_config_prefixes(ctx, cfg);
	ctx->disabled = (cfg->proc_prefix_count == 0) ? 1 : 0;
	if (ctx->disabled) {
		TF_LOG_INFO("[proc] collector disabled: set proc_prefix to enable process metrics");
	}

	return 0;
}

static void proc_destroy(struct tf_collector *col)
{
	if (col && col->ctx) {
		free(col->ctx);
		col->ctx = NULL;
	}
}

static int proc_collect(struct proc_ctx *ctx, const struct agent_config *cfg)
{
	(void)cfg;
	if (ctx->disabled) {
		memset(&ctx->last_payload, 0, sizeof(ctx->last_payload));
		return 0;
	}

	time_t now = time(NULL);
	if (now == (time_t)-1 || ctx->last_scan_time == 0 || (now - ctx->last_scan_time) >= TF_TRACKER_INTERVAL_SEC) {
		tracker_scan_proc(ctx);
	}

	unsigned long long total_diff = ctx->cpu_total_diff;
	if (total_diff == 0) {
		total_diff = 1;
	}

	uint32_t inst_count[MAX_COMM_PREFIX]  = { 0 };
	uint64_t cpu_sum_x10[MAX_COMM_PREFIX] = { 0 };
	uint64_t rss_sum_kb[MAX_COMM_PREFIX]  = { 0 };

	for (size_t group_idx = 0; group_idx < ctx->watch_group_count; ++group_idx) {
		const struct watch_group *grp = &ctx->watch_groups[group_idx];
		for (size_t i = 0; i < grp->list.count; ++i) {
			long pid = grp->list.pids[i];

			char stat_path[TF_PATH_BUF] = { 0 };
			(void)snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", pid);

			char comm[TF_PROC_STAT_BUF] = { 0 };
			int parsed_pid              = 0;
			unsigned long long ticks    = parse_stat(stat_path, &parsed_pid, comm);
			if (!ticks || parsed_pid != pid) {
				continue;
			}

			struct proc_prev *slot        = find_slot(ctx, pid);
			unsigned long long prev_ticks = slot->ticks;
			slot->ticks                   = ticks;

			if (prev_ticks == 0 || ticks < prev_ticks) {
				continue;
			}

			unsigned long long delta  = ticks - prev_ticks;
			unsigned long long scaled = delta * (unsigned long long)TF_CPU_PERCENT_SCALE * (unsigned long long)get_cpu_count(ctx);
			unsigned long long value  = scaled / total_diff; /* 0.1% */

			uint32_t rss_kb = parse_rss_kb(pid);

			inst_count[group_idx]++;
			cpu_sum_x10[group_idx] += value;
			rss_sum_kb[group_idx] += rss_kb;
		}
	}

	memset(&ctx->last_payload, 0, sizeof(ctx->last_payload));
	uint8_t out_groups = 0;

	for (size_t index = 0; index < ctx->watch_group_count && out_groups < TF_MAX_PROC_GROUPS; ++index) {
		if (inst_count[index] == 0) {
			continue;
		}

		struct proc_group_entry *dst = &ctx->last_payload.groups[out_groups];

		strncpy(dst->name, ctx->watch_groups[index].name, sizeof(dst->name) - 1);
		dst->name[sizeof(dst->name) - 1] = '\0';

		if (inst_count[index] > (uint32_t)UINT16_MAX) {
			dst->inst_count = (uint16_t)UINT16_MAX;
		}
		else {
			dst->inst_count = (uint16_t)inst_count[index];
		}

		if (cpu_sum_x10[index] > (uint64_t)UINT16_MAX) {
			dst->cpu_pct_x10 = (uint16_t)UINT16_MAX;
		}
		else {
			dst->cpu_pct_x10 = (uint16_t)cpu_sum_x10[index];
		}

		if (rss_sum_kb[index] > (uint64_t)UINT32_MAX) {
			dst->rss_kb_sum = UINT32_MAX;
		}
		else {
			dst->rss_kb_sum = (uint32_t)rss_sum_kb[index];
		}

		out_groups++;
	}

	ctx->last_payload.group_count = out_groups;
	return 0;
}

static int proc_push(struct proc_ctx *ctx, struct tlv_writer *wrt)
{
	if (ctx->disabled) {
		return 0;
	}

	uint8_t payload[1 + TF_MAX_PROC_GROUPS * TF_PROC_GROUP_PAYLOAD_LEN] = { 0 };
	uint8_t *payload_cursor                                             = payload;

	*payload_cursor++ = ctx->last_payload.group_count;

	for (uint8_t i = 0; i < ctx->last_payload.group_count && i < TF_MAX_PROC_GROUPS; ++i) {
		const struct proc_group_entry *group = &ctx->last_payload.groups[i];

		memcpy(payload_cursor, group->name, sizeof(group->name));
		payload_cursor += sizeof(group->name);

		buf_put_be_u16(&payload_cursor, group->inst_count);
		buf_put_be_u16(&payload_cursor, group->cpu_pct_x10);
		buf_put_be_u32(&payload_cursor, group->rss_kb_sum);
	}

	return tlv_put(wrt, TF_TYPE_PROC, payload, (uint8_t)(payload_cursor - payload));
}

static int proc_collect_api(struct tf_collector *col, const struct agent_config *cfg, struct sample_context *sctx)
{
	struct proc_ctx *ctx = (struct proc_ctx *)col->ctx;
	if (!ctx) return -1;

	ctx->cpu_total_diff = sctx ? sctx->cpu_total_diff : 1;
	return proc_collect(ctx, cfg);
}

static int proc_push_api(struct tf_collector *col, struct tlv_writer *wrt)
{
	struct proc_ctx *ctx = (struct proc_ctx *)col->ctx;
	if (!ctx) return -1;
	return proc_push(ctx, wrt);
}

static void proc_print(struct tf_collector *col, FILE *out)
{
	struct proc_ctx *ctx = (struct proc_ctx *)col->ctx;
	if (!ctx) return;
	if (ctx->disabled) {
		(void)fprintf(out, "PROC: disabled (set proc_prefix to enable)\n");
		return;
	}

	(void)fprintf(out, "PROC: groups=%u\n", ctx->last_payload.group_count);
	for (uint8_t i = 0; i < ctx->last_payload.group_count && i < TF_MAX_PROC_GROUPS; ++i) {
		const struct proc_group_entry *group = &ctx->last_payload.groups[i];
		(void)fprintf(out, "  - %s: inst=%u cpu=%u.%1u%%%% rss_sum=%u kB\n", group->name, (unsigned)group->inst_count,
		              (unsigned)(group->cpu_pct_x10 / TF_PERCENT_DIV), (unsigned)(group->cpu_pct_x10 % TF_PERCENT_DIV), (unsigned)group->rss_kb_sum);
	}
}

struct tf_collector proc_collector = {
	.name             = "proc",
	.ctx              = NULL,
	.init             = proc_init,
	.destroy          = proc_destroy,
	.collect          = proc_collect_api,
	.push             = proc_push_api,
	.print            = proc_print,
};
