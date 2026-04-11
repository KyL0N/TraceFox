#ifndef TRACEFOX_H
#define TRACEFOX_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define TF_MAGIC           0x5446
#define TF_VERSION         2
#define TF_MAX_INTERFACES  4
#define TF_MAX_DISKS       4
#define TF_MAX_FS          4
#define TF_MAX_PROC        10
#define TF_PROC_TRACK      64
#define TF_MAX_PROC_GROUPS 8

#define TF_MAX_PAYLOAD_SIZE 1024

/* 默认配置 */
#define TF_DEFAULT_SERVER_HOST  "127.0.0.1"
#define TF_DEFAULT_SERVER_PORT  9000
#define TF_DEFAULT_INTERVAL_SEC 5

/* 协议对齐的名称/挂载点字段大小 */
#define TF_NET_NAME_SIZE  8
#define TF_DISK_NAME_SIZE 8
#define TF_FS_MOUNT_SIZE  16
#define TF_PROC_NAME_SIZE 16

/* 各 TLV payload 长度（字节） */
#define TF_CPU_PAYLOAD_LEN        10
#define TF_MEM_PAYLOAD_LEN        18
#define TF_NET_ENTRY_PAYLOAD_LEN  24
#define TF_DISK_ENTRY_PAYLOAD_LEN 66
#define TF_FS_ENTRY_PAYLOAD_LEN   26
#define TF_PROC_GROUP_PAYLOAD_LEN 24

/* 发送/文件缓冲与帧头 */
#define TF_FRAME_BUF_SIZE  1400
#define TF_HEADER_LEN      8
#define TF_HEADER_VER      0x01
#define TF_FRAME_LEN_BYTES 2

/* 序列化/显示用常量 */
#define TF_BYTE_MASK         0xFF
#define TF_PERCENT_DIV       10
#define TF_LOAD_SCALE        100
#define TF_CPU_PERCENT_SCALE 1000
#define TF_PCT10_MAX         1000
#define TF_KB                1024

/* 行/路径/键缓冲区长度 */
#define TF_LINE_BUF_SMALL       256
#define TF_LINE_BUF_NET         512
#define TF_PATH_BUF             64
#define TF_KEY_BUF              64
#define TF_UNIT_BUF             16
#define TF_PROC_COMM_MAX        15
#define TF_PROC_STAT_BUF        16
#define TF_DISK_NAME_BUF        32
#define TF_NET_IFACE_BUF        16
#define TF_NET_IFACE_SCANF      15
#define TF_NET_DEV_SSCANF_FMT   " %15[^:]: %llu %*u %*u %*u %*u %*u %*u %*u %llu"
#define TF_FS_DEV_BUF           64
#define TF_FS_MOUNT_BUF         128
#define TF_FS_TYPE_BUF          32
#define TF_FS_OPTS_BUF          128
#define TF_FSCANF_MOUNTS_FMT    "%63s %127s %31s %127s %d %d"
#define TF_DISK_STAT_MIN        14
#define TF_DISK_CACHE_NAME_LEN  16
#define TF_DISK_SSCANF_FMT      "%u %u %31s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu"
#define TF_SSCANF_KEY_MAX       63
#define TF_SSCANF_MOUNT_MAX     127
#define TF_SSCANF_TYPE_MAX      31
#define TF_SSCANF_NAME_MAX      31
#define TF_TRACKER_INTERVAL_SEC 5
#define TF_FSCANF_STATUS_FMT    "%63s %lu %15s"
#define TF_FSCANF_MEMINFO_FMT   "%63s %lu"

#define TF_TYPE_CPU  0x01
#define TF_TYPE_MEM  0x02
#define TF_TYPE_NET  0x04
#define TF_TYPE_DISK 0x05
#define TF_TYPE_FS   0x06
#define TF_TYPE_PROC 0x07

#define TF_MAX_COMM_PREFIX 32
#define TF_COMM_PREFIX_LEN 32

struct agent_config
{
	char server_host[64];
	uint16_t server_port;
	uint16_t interval_sec;
	char proc_prefixes[TF_MAX_COMM_PREFIX][TF_COMM_PREFIX_LEN];
	size_t proc_prefix_count;
};

struct cpu_payload
{
	uint16_t user;
	uint16_t system;
	uint16_t idle;
	uint16_t iowait;
	uint16_t irq;
};

struct mem_payload
{
	uint32_t mem_total_kb;
	uint32_t mem_free_kb;
	uint32_t mem_available_kb;
};

struct load_payload
{
	uint16_t load1_x100;
	uint16_t load5_x100;
	uint16_t load15_x100;
};

struct net_entry
{
	char name[TF_NET_NAME_SIZE];
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

struct disk_entry
{
	char name[TF_DISK_NAME_SIZE];
	/* cumulative counters from /proc/diskstats (64-bit for long uptime) */
	uint64_t reads_completed;
	uint64_t writes_completed;
	uint64_t sectors_read;
	uint64_t sectors_written;
	uint64_t read_ms;
	uint64_t write_ms;
	/* per-interval envelope / utilization */
	uint32_t read_iops_delta;
	uint32_t write_iops_delta;
	uint16_t io_util_pct_x10; /* 0.1% precision */
};

struct fs_entry
{
	char mount[TF_FS_MOUNT_SIZE];
	uint64_t total_kb;
	uint16_t used_pct_x10; /* 0.1% precision */
};

/* Process group envelope payload: aggregated by process name */
struct proc_group_entry
{
	char name[TF_PROC_NAME_SIZE];
	uint16_t inst_count;
	uint16_t cpu_pct_x10;
	uint32_t rss_kb_sum;
};

struct proc_payload
{
	uint8_t group_count;
	struct proc_group_entry groups[TF_MAX_PROC_GROUPS];
};

struct tlv_writer
{
	uint8_t * buffer;
	size_t len;
	size_t cap;
};

struct sample_context
{
	unsigned long long cpu_total_diff;
};

struct tf_collector
{
	const char * name;
	void * ctx; /* 状态隔离：每个收集器独占的内部状态 */

	/* 生命周期与初始化 */
	int (*init)(struct tf_collector * col, const struct agent_config * cfg);
	void (*destroy)(struct tf_collector * col);

	/* 对外统一执行采集并写入，内部再解耦为 collect 和 push */
	int (*collect_and_push)(struct tf_collector * col, struct tlv_writer * wrt, const struct agent_config * cfg, struct sample_context * sctx);

	/* 打印调试信息，传入 FILE * 便于重定向 */
	void (*print)(struct tf_collector * col, FILE * out);
};

/* config helper: add a proc prefix to agent_config */
static inline __attribute__((unused)) void config_add_proc_prefix(struct agent_config * cfg, const char * prefix)
{
	if (cfg->proc_prefix_count >= TF_MAX_COMM_PREFIX) {
		return;
	}
	strncpy(cfg->proc_prefixes[cfg->proc_prefix_count], prefix, TF_COMM_PREFIX_LEN - 1);
	cfg->proc_prefixes[cfg->proc_prefix_count][TF_COMM_PREFIX_LEN - 1] = '\0';
	cfg->proc_prefix_count++;
}

/* tlv.c */
int tlv_init(struct tlv_writer * writer, uint8_t * buf, size_t cap, uint32_t timestamp, uint32_t seq);
int tlv_put(struct tlv_writer * writer, uint8_t type, const void * value, uint8_t len);

#endif
