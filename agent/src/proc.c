#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include "tracefox.h"

#define PID_HASH(pid)   ((unsigned long)((unsigned int)(pid) * 2654435761u) % TF_PROC_TRACK)
#define THREAD_HASH(pid, tid)                                                                                                                                    \
	((size_t)(((uint64_t)(uint32_t)(pid) * UINT64_C(11400714819323198485)) ^ ((uint64_t)(uint32_t)(tid) * UINT64_C(14029467366897019727))) % \
	 (uint64_t)TF_THREAD_TRACK)

struct pid_list
{
	long pids[TF_PROC_TRACK];
	size_t count;
};

struct watch_group
{
	char name[TF_COMM_PREFIX_LEN];
	struct pid_list list;
};

struct proc_prev
{
	long pid;
	unsigned long long ticks;
};

struct task_stat
{
	long id;
	char comm[TF_PROC_NAME_SIZE];
	char state;
	unsigned long long ticks;
	unsigned long long starttime;
};

struct thread_prev
{
	long pid;
	long tid;
	unsigned long long starttime;
	unsigned long long ticks;
	uint32_t generation;
};

struct thread_candidate
{
	char name[TF_PROC_NAME_SIZE];
	uint32_t pid;
	uint32_t tid;
	uint32_t inst_count;
	uint64_t cpu_pct_x10;
};

struct proc_ctx
{
	struct proc_prev history[TF_PROC_TRACK];
	struct thread_prev thread_history[TF_THREAD_TRACK];
	struct thread_candidate thread_candidates[TF_THREAD_CANDIDATES];
	struct watch_group watch_groups[TF_MAX_COMM_PREFIX];
	int disabled;
	int thread_frame_warned;
	size_t cpu_count;
	size_t watch_group_count;
	uint32_t thread_generation;
	uint8_t thread_mode;
	uint8_t thread_top_n;
	uint8_t thread_include_tid;
	time_t last_scan_time;
	unsigned long long cpu_total_diff;
	struct proc_payload last_payload;
	struct thread_payload last_thread_payload;
};

static void apply_config_prefixes(struct proc_ctx *ctx, const struct agent_config *cfg)
{
	for (size_t i = 0; i < cfg->proc_prefix_count && i < TF_MAX_COMM_PREFIX; ++i) {
		strncpy(ctx->watch_groups[i].name, cfg->proc_prefixes[i], TF_COMM_PREFIX_LEN - 1);
		ctx->watch_groups[i].name[TF_COMM_PREFIX_LEN - 1] = '\0';
		ctx->watch_groups[i].list.count                = 0;
	}
	ctx->watch_group_count = cfg->proc_prefix_count;
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

static int parse_task_stat(const char *path, struct task_stat *task)
{
	if (!path || !task) {
		return -1;
	}

	FILE *stat_fp = fopen(path, "r");
	if (!stat_fp) {
		return -1;
	}

	char buf[512];
	if (!fgets(buf, (int)sizeof(buf), stat_fp)) {
		(void)fclose(stat_fp);
		return -1;
	}
	(void)fclose(stat_fp);

	long id = 0;
	if (sscanf(buf, "%ld ", &id) != 1 || id <= 0) { // NOLINT
		return -1;
	}

	char *left  = strchr(buf, '(');
	char *right = strrchr(buf, ')');
	if (!left || !right || right <= left) {
		return -1;
	}

	size_t comm_len = (size_t)(right - left - 1);
	if (comm_len >= sizeof(task->comm)) {
		comm_len = sizeof(task->comm) - 1U;
	}

	memset(task, 0, sizeof(*task));
	task->id = id;
	memcpy(task->comm, left + 1, comm_len);
	task->comm[comm_len] = '\0';

	unsigned long long utime = 0ULL;
	unsigned long long stime = 0ULL;
	unsigned long long starttime = 0ULL;
	char *cursor = right + 1;
	while (*cursor != '\0' && isspace((unsigned char)*cursor)) cursor++;
	if (*cursor == '\0') {
		return -1;
	}
	task->state = *cursor++;

	for (int field = 4; field <= 22; ++field) {
		while (*cursor != '\0' && isspace((unsigned char)*cursor)) cursor++;
		if (*cursor == '\0') {
			return -1;
		}

		if (field == 14 || field == 15 || field == 22) {
			char *number_end = NULL;
			errno = 0;
			unsigned long long value = strtoull(cursor, &number_end, 10);
			if (errno != 0 || !number_end || number_end == cursor) {
				return -1;
			}
			if (field == 14) utime = value;
			else if (field == 15) stime = value;
			else starttime = value;
		}

		while (*cursor != '\0' && !isspace((unsigned char)*cursor)) cursor++;
	}

	task->ticks     = utime + stime;
	task->starttime = starttime;
	return 0;
}

static unsigned long long parse_stat(const char *path, int *pid_out, char *comm_out)
{
	struct task_stat task = { 0 };
	if (parse_task_stat(path, &task) != 0) {
		return 0;
	}

	*pid_out = (int)task.id;
	strncpy(comm_out, task.comm, TF_PROC_STAT_BUF - 1U);
	comm_out[TF_PROC_STAT_BUF - 1U] = '\0';
	return task.ticks;
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

static struct thread_prev *find_thread_slot(struct proc_ctx *ctx, long pid, long tid, unsigned long long starttime)
{
	size_t idx = THREAD_HASH(pid, tid);

	for (size_t probe = 0; probe < TF_THREAD_TRACK; ++probe) {
		struct thread_prev *slot = &ctx->thread_history[(idx + probe) % TF_THREAD_TRACK];

		if (slot->pid == pid && slot->tid == tid) {
			if (slot->starttime != starttime) {
				slot->starttime = starttime;
				slot->ticks     = 0ULL;
			}
			return slot;
		}

		if (slot->pid == 0) {
			slot->pid       = pid;
			slot->tid       = tid;
			slot->starttime = starttime;
			slot->ticks     = 0ULL;
			return slot;
		}
	}

	return NULL;
}

static void thread_history_gc(struct proc_ctx *ctx)
{
	for (size_t i = 0; i < TF_THREAD_TRACK; ++i) {
		if (ctx->thread_history[i].pid != 0 && ctx->thread_history[i].generation != ctx->thread_generation) {
			memset(&ctx->thread_history[i], 0, sizeof(ctx->thread_history[i]));
		}
	}
}

static size_t thread_state_index(char state)
{
	switch (state) {
	case 'R': return TF_THREAD_STATE_RUNNING;
	case 'S': return TF_THREAD_STATE_SLEEPING;
	case 'D': return TF_THREAD_STATE_DISK_SLEEP;
	case 'T':
	case 't': return TF_THREAD_STATE_STOPPED;
	case 'Z': return TF_THREAD_STATE_ZOMBIE;
	case 'I': return TF_THREAD_STATE_IDLE;
	default: return TF_THREAD_STATE_OTHER;
	}
}

static void increment_u16(uint16_t *value, uint8_t *flags)
{
	if (*value < UINT16_MAX) {
		(*value)++;
	}
	else {
		*flags |= TF_THREAD_FLAG_TRUNCATED;
	}
}

static int add_thread_candidate(struct proc_ctx *ctx, size_t *candidate_count, const struct task_stat *task, long pid, uint64_t cpu_pct_x10)
{
	for (size_t i = 0; i < *candidate_count; ++i) {
		struct thread_candidate *candidate = &ctx->thread_candidates[i];
		int same = 0;

		if (ctx->thread_include_tid) {
			same = candidate->pid == (uint32_t)pid && candidate->tid == (uint32_t)task->id;
		}
		else {
			same = strcmp(candidate->name, task->comm) == 0;
		}

		if (same) {
			if (candidate->inst_count < UINT32_MAX) {
				candidate->inst_count++;
			}
			candidate->cpu_pct_x10 += cpu_pct_x10;
			return 0;
		}
	}

	if (*candidate_count >= TF_THREAD_CANDIDATES || pid <= 0 || task->id <= 0 || (unsigned long)pid > (unsigned long)UINT32_MAX ||
	    (unsigned long)task->id > (unsigned long)UINT32_MAX) {
		return -1;
	}

	struct thread_candidate *candidate = &ctx->thread_candidates[*candidate_count];
	memset(candidate, 0, sizeof(*candidate));
	strncpy(candidate->name, task->comm, sizeof(candidate->name) - 1U);
	candidate->pid           = ctx->thread_include_tid ? (uint32_t)pid : 0U;
	candidate->tid           = ctx->thread_include_tid ? (uint32_t)task->id : 0U;
	candidate->inst_count    = 1U;
	candidate->cpu_pct_x10   = cpu_pct_x10;
	(*candidate_count)++;
	return 0;
}

static int compare_thread_candidates(const void *lhs_ptr, const void *rhs_ptr)
{
	const struct thread_candidate *lhs = (const struct thread_candidate *)lhs_ptr;
	const struct thread_candidate *rhs = (const struct thread_candidate *)rhs_ptr;

	if (lhs->cpu_pct_x10 > rhs->cpu_pct_x10) return -1;
	if (lhs->cpu_pct_x10 < rhs->cpu_pct_x10) return 1;
	return strcmp(lhs->name, rhs->name);
}

static void copy_thread_candidate(struct thread_top_entry *dst, const struct thread_candidate *src)
{
	memset(dst, 0, sizeof(*dst));
	strncpy(dst->name, src->name, sizeof(dst->name) - 1U);
	dst->inst_count = src->inst_count > (uint32_t)UINT16_MAX ? UINT16_MAX : (uint16_t)src->inst_count;
	dst->cpu_pct_x10 = src->cpu_pct_x10 > (uint64_t)UINT16_MAX ? UINT16_MAX : (uint16_t)src->cpu_pct_x10;
	dst->pid = src->pid;
	dst->tid = src->tid;
}

static void collect_thread_group(struct proc_ctx *ctx, const struct watch_group *group, struct thread_group_entry *out)
{
	memset(out, 0, sizeof(*out));
	strncpy(out->name, group->name, sizeof(out->name) - 1U);
	if (ctx->thread_include_tid) {
		out->flags |= TF_THREAD_FLAG_INCLUDE_TID;
	}

	size_t candidate_count = 0;
	memset(ctx->thread_candidates, 0, sizeof(ctx->thread_candidates));

	for (size_t pid_index = 0; pid_index < group->list.count; ++pid_index) {
		long pid = group->list.pids[pid_index];
		char task_dir_path[TF_PATH_BUF] = { 0 };
		(void)snprintf(task_dir_path, sizeof(task_dir_path), "/proc/%ld/task", pid);

		DIR *task_dir = opendir(task_dir_path);
		if (!task_dir) {
			continue;
		}

		size_t scanned_for_pid = 0;
		struct dirent *task_entry = NULL;
		while ((task_entry = readdir(task_dir))) {
			if (!isdigit((unsigned char)task_entry->d_name[0])) {
				continue;
			}

			if (scanned_for_pid >= TF_THREAD_SCAN_LIMIT_PER_PID) {
				out->flags |= TF_THREAD_FLAG_TRUNCATED;
				break;
			}

			char *end = NULL;
			errno = 0;
			long tid = strtol(task_entry->d_name, &end, 10);
			if (errno != 0 || tid <= 0 || !end || *end != '\0') {
				continue;
			}

			char stat_path[TF_PATH_BUF] = { 0 };
			(void)snprintf(stat_path, sizeof(stat_path), "/proc/%ld/task/%ld/stat", pid, tid);
			struct task_stat task = { 0 };
			if (parse_task_stat(stat_path, &task) != 0 || task.id != tid) {
				continue;
			}

			scanned_for_pid++;
			increment_u16(&out->total_threads, &out->flags);
			size_t state_index = thread_state_index(task.state);
			increment_u16(&out->state_counts[state_index], &out->flags);

			if (ctx->thread_mode != TF_THREAD_MODE_TOP) {
				continue;
			}

			uint64_t cpu_pct_x10 = 0U;
			struct thread_prev *slot = find_thread_slot(ctx, pid, tid, task.starttime);
			if (!slot) {
				out->flags |= TF_THREAD_FLAG_TRUNCATED;
			}
			else {
				unsigned long long previous_ticks = slot->ticks;
				slot->ticks                     = task.ticks;
				slot->generation                = ctx->thread_generation;

				if (previous_ticks != 0ULL && task.ticks >= previous_ticks) {
					unsigned long long delta = task.ticks - previous_ticks;
					unsigned long long total_diff = ctx->cpu_total_diff == 0ULL ? 1ULL : ctx->cpu_total_diff;
					uint64_t scaled = (uint64_t)delta * (uint64_t)TF_CPU_PERCENT_SCALE * (uint64_t)get_cpu_count(ctx);
					cpu_pct_x10 = scaled / (uint64_t)total_diff;
				}
			}

			if (add_thread_candidate(ctx, &candidate_count, &task, pid, cpu_pct_x10) != 0) {
				out->flags |= TF_THREAD_FLAG_TRUNCATED;
			}
		}

		(void)closedir(task_dir);
	}

	if (ctx->thread_mode != TF_THREAD_MODE_TOP || candidate_count == 0) {
		return;
	}

	qsort(ctx->thread_candidates, candidate_count, sizeof(ctx->thread_candidates[0]), compare_thread_candidates);
	size_t top_count = candidate_count;
	if (top_count > (size_t)ctx->thread_top_n) top_count = (size_t)ctx->thread_top_n;
	if (top_count > TF_MAX_THREAD_TOP_N) top_count = TF_MAX_THREAD_TOP_N;

	out->top_count = (uint8_t)top_count;
	for (size_t i = 0; i < top_count; ++i) {
		copy_thread_candidate(&out->top[i], &ctx->thread_candidates[i]);
	}
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

		char comm[TF_COMM_PREFIX_LEN];
		if (!fgets(comm, sizeof(comm), comm_fp)) {
			(void)fclose(comm_fp);
			continue;
		}
		(void)fclose(comm_fp);

		size_t len = strlen(comm);
		if (len > 0 && comm[len - 1] == '\n') {
			comm[len - 1] = '\0';
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
	ctx->disabled           = (cfg->proc_prefix_count == 0) ? 1 : 0;
	ctx->thread_mode        = cfg->thread_mode;
	ctx->thread_top_n       = cfg->thread_top_n;
	ctx->thread_include_tid = cfg->thread_include_tid;
	if (ctx->disabled) {
		TF_LOG_INFO("[proc] collector disabled: set proc_prefix to enable process metrics");
	}
	else if (ctx->thread_mode == TF_THREAD_MODE_OFF) {
		TF_LOG_INFO("[thread] collector disabled by thread_mode=off");
	}
	else {
		TF_LOG_INFO("[thread] collector enabled: mode=%s top_n=%u include_tid=%s", ctx->thread_mode == TF_THREAD_MODE_TOP ? "top" : "summary",
		            (unsigned)ctx->thread_top_n, ctx->thread_include_tid ? "true" : "false");
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
		memset(&ctx->last_thread_payload, 0, sizeof(ctx->last_thread_payload));
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

	uint32_t inst_count[TF_MAX_COMM_PREFIX]  = { 0 };
	uint64_t cpu_sum_x10[TF_MAX_COMM_PREFIX] = { 0 };
	uint64_t rss_sum_kb[TF_MAX_COMM_PREFIX]  = { 0 };

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

	memset(&ctx->last_thread_payload, 0, sizeof(ctx->last_thread_payload));
	if (ctx->thread_mode != TF_THREAD_MODE_OFF) {
		ctx->thread_generation++;
		if (ctx->thread_generation == 0U) {
			ctx->thread_generation = 1U;
			memset(ctx->thread_history, 0, sizeof(ctx->thread_history));
		}

		uint8_t thread_groups = 0;
		for (size_t index = 0; index < ctx->watch_group_count && thread_groups < TF_MAX_PROC_GROUPS; ++index) {
			struct thread_group_entry candidate = { 0 };
			collect_thread_group(ctx, &ctx->watch_groups[index], &candidate);
			if (candidate.total_threads == 0U) {
				continue;
			}

			ctx->last_thread_payload.groups[thread_groups] = candidate;
			thread_groups++;
		}
		ctx->last_thread_payload.group_count = thread_groups;
		thread_history_gc(ctx);
	}
	return 0;
}

static int thread_push(struct proc_ctx *ctx, struct tlv_writer *wrt)
{
	for (uint8_t group_index = 0; group_index < ctx->last_thread_payload.group_count; ++group_index) {
		const struct thread_group_entry *group = &ctx->last_thread_payload.groups[group_index];
		uint8_t emit_top_count = group->top_count;
		int top_count_capped = 0;
		if (emit_top_count > TF_MAX_THREAD_TOP_N) {
			emit_top_count = TF_MAX_THREAD_TOP_N;
			top_count_capped = 1;
		}
		size_t remaining = wrt->cap > wrt->len ? wrt->cap - wrt->len : 0U;

		while (emit_top_count > 0U && 2U + TF_THREAD_GROUP_HEADER_PAYLOAD_LEN + (size_t)emit_top_count * TF_THREAD_ENTRY_PAYLOAD_LEN > remaining) {
			emit_top_count--;
		}

		if (2U + TF_THREAD_GROUP_HEADER_PAYLOAD_LEN > remaining) {
			if (!ctx->thread_frame_warned) {
				TF_LOG_WARN("[thread] frame budget exhausted; some thread groups were dropped");
				ctx->thread_frame_warned = 1;
			}
			break;
		}

		uint8_t payload[TF_THREAD_GROUP_HEADER_PAYLOAD_LEN + TF_MAX_THREAD_TOP_N * TF_THREAD_ENTRY_PAYLOAD_LEN] = { 0 };
		uint8_t *payload_cursor = payload;
		uint8_t flags = group->flags;
		if (top_count_capped || emit_top_count < group->top_count) {
			flags |= TF_THREAD_FLAG_TRUNCATED;
			if (!ctx->thread_frame_warned) {
				TF_LOG_WARN("[thread] frame budget reduced the configured top-N payload");
				ctx->thread_frame_warned = 1;
			}
		}

		memcpy(payload_cursor, group->name, sizeof(group->name));
		payload_cursor += sizeof(group->name);
		buf_put_be_u16(&payload_cursor, group->total_threads);
		*payload_cursor++ = flags;
		for (size_t state_index = 0; state_index < TF_THREAD_STATE_COUNT; ++state_index) {
			buf_put_be_u16(&payload_cursor, group->state_counts[state_index]);
		}
		*payload_cursor++ = emit_top_count;

		for (uint8_t top_index = 0; top_index < emit_top_count; ++top_index) {
			const struct thread_top_entry *entry = &group->top[top_index];
			memcpy(payload_cursor, entry->name, sizeof(entry->name));
			payload_cursor += sizeof(entry->name);
			buf_put_be_u16(&payload_cursor, entry->inst_count);
			buf_put_be_u16(&payload_cursor, entry->cpu_pct_x10);
			buf_put_be_u32(&payload_cursor, entry->pid);
			buf_put_be_u32(&payload_cursor, entry->tid);
		}

		size_t payload_len = (size_t)(payload_cursor - payload);
		if (payload_len > UINT8_MAX || tlv_put(wrt, TF_TYPE_THREAD, payload, (uint8_t)payload_len) != 0) {
			return -1;
		}
	}

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

	if (tlv_put(wrt, TF_TYPE_PROC, payload, (uint8_t)(payload_cursor - payload)) != 0) {
		return -1;
	}

	if (ctx->thread_mode != TF_THREAD_MODE_OFF) {
		return thread_push(ctx, wrt);
	}

	return 0;
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

	if (ctx->thread_mode == TF_THREAD_MODE_OFF) {
		(void)fprintf(out, "THREAD: disabled\n");
		return;
	}

	(void)fprintf(out, "THREAD: groups=%u mode=%s\n", ctx->last_thread_payload.group_count, ctx->thread_mode == TF_THREAD_MODE_TOP ? "top" : "summary");
	for (uint8_t group_index = 0; group_index < ctx->last_thread_payload.group_count; ++group_index) {
		const struct thread_group_entry *group = &ctx->last_thread_payload.groups[group_index];
		(void)fprintf(out, "  - %s: total=%u states(R=%u,S=%u,D=%u,T=%u,Z=%u,I=%u,other=%u) truncated=%s\n", group->name,
		              (unsigned)group->total_threads, (unsigned)group->state_counts[TF_THREAD_STATE_RUNNING],
		              (unsigned)group->state_counts[TF_THREAD_STATE_SLEEPING], (unsigned)group->state_counts[TF_THREAD_STATE_DISK_SLEEP],
		              (unsigned)group->state_counts[TF_THREAD_STATE_STOPPED], (unsigned)group->state_counts[TF_THREAD_STATE_ZOMBIE],
		              (unsigned)group->state_counts[TF_THREAD_STATE_IDLE], (unsigned)group->state_counts[TF_THREAD_STATE_OTHER],
		              (group->flags & TF_THREAD_FLAG_TRUNCATED) != 0U ? "yes" : "no");
		for (uint8_t top_index = 0; top_index < group->top_count; ++top_index) {
			const struct thread_top_entry *entry = &group->top[top_index];
			(void)fprintf(out, "      %s: inst=%u cpu=%u.%1u%%%%", entry->name, (unsigned)entry->inst_count,
			              (unsigned)(entry->cpu_pct_x10 / TF_PERCENT_DIV), (unsigned)(entry->cpu_pct_x10 % TF_PERCENT_DIV));
			if ((group->flags & TF_THREAD_FLAG_INCLUDE_TID) != 0U) {
				(void)fprintf(out, " pid=%u tid=%u", (unsigned)entry->pid, (unsigned)entry->tid);
			}
			(void)fprintf(out, "\n");
		}
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
