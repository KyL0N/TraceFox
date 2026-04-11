# TraceFox

轻量级嵌入式系统监控方案，适用于 Linux 目标板。

## 架构

```
tracefox-agent (C)          轻量采集端，读取 /proc & statvfs
       │
       │  UDP TLV v2 (< 1400 bytes)
       ▼
metrics_forwarder (Python)  解析 TLV → Prometheus 格式 → HTTP POST
       │
       ▼
VictoriaMetrics             高压缩比时序数据库，ARM64 原生支持
       │
       ▼
Grafana                     可视化大盘、告警、多 Host 筛选
```

## 目录结构

```
TraceFox/
├── agent/                      C 采集端
│   ├── Makefile
│   ├── include/tracefox.h      数据结构与常量定义
│   ├── src/
│   │   ├── main.c              主循环 + TLV 组装 + UDP 发送
│   │   ├── tlv.c               帧头 + TLV 编码器
│   │   ├── cpu.c               CPU 使用率 (/proc/stat)
│   │   ├── mem.c               内存 + 负载 (/proc/meminfo, /proc/loadavg)
│   │   ├── net.c               网络接口计数器 (/proc/net/dev)
│   │   ├── disk.c              磁盘 I/O 统计 (/proc/diskstats)
│   │   ├── fs.c                文件系统用量 (statvfs)
│   │   └── proc.c              进程组聚合 (按进程名前缀)
│   └── config/agent.conf       Agent 配置文件（启动时自动读取）
├── server/                     服务端
│   ├── tracefox_protocol.py    TLV v2 帧解析器（共享模块）
│   ├── metrics_forwarder.py    核心转发：UDP → Prometheus → VictoriaMetrics
│   ├── test_server.py          最小 UDP 调试服务器（终端打印）
│   ├── Dockerfile              Forwarder 容器镜像
│   └── requirements.txt        Python 依赖说明
├── grafana/
│   ├── dashboards/
│   │   └── tracefox-overview.json    预制 Grafana 大盘
│   └── provisioning/
│       ├── datasources/datasource.yml  VictoriaMetrics 数据源
│       ├── dashboards/dashboard.yml    大盘自动加载配置
│       └── alerting/rules.yml          告警规则（CPU/MEM/Disk/FS/Agent Down）
├── docker-compose.yml          一键部署（Forwarder + VM + Grafana）
├── .env.example                环境变量模板
└── .gitignore
```

## TLV v2 协议格式

帧头（12 字节，大端）：

| 字段 | 大小 | 说明 |
|------|------|------|
| magic | 2 | `0x5446`（`'TF'`） |
| version | 1 | `0x02` |
| reserved | 1 | `0x00` |
| timestamp | 4 | Unix 秒 |
| sequence | 4 | 单调递增帧序号 |

TLV 体：`Type(1) + Length(1) + Value(变长)`

| Type | 含义 | 内容 |
|------|------|------|
| `0x01` | CPU | user/system/idle/iowait/irq（千分比，uint16） |
| `0x02` | 内存 + 负载 | total/free/available（KB），load1/5/15（×100） |
| `0x04` | 网络 | 每接口 rx/tx 字节数（累计） |
| `0x05` | 磁盘 | 每设备读写计数/扇区/延迟/IOPS/利用率 |
| `0x06` | 文件系统 | 每挂载点 total_kb + used_pct |
| `0x07` | 进程组 | 按名称聚合的实例数/CPU%/RSS |

单帧始终 < 1400 字节，避免 MTU 分片。

## 快速开始

### 1. 编译 Agent

```bash
cd agent
make                    # 默认 release 构建
make debug              # 调试构建（含 -g -O0）
```

产物：`agent/bin/tracefox-agent`

### 2. 部署服务端（Docker Compose）

```bash
cp .env.example .env    # 编辑 TRACEFOX_HOST_LABEL、GRAFANA_PASSWORD 等
sudo docker compose up -d
```

启动后：
- **VictoriaMetrics**：`http://<IP>:8428`
- **Grafana**：`http://<IP>:3000`（账号 `admin`，密码见 `.env` 中 `GRAFANA_PASSWORD`，请务必修改默认密码）
- **Forwarder**：监听 UDP `:9000`

### 3. 启动 Agent

```bash
./agent/bin/tracefox-agent -h <服务端IP> -p 9000 -i 5
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-h` | 服务端地址 | `127.0.0.1` |
| `-p` | UDP 端口 | `9000` |
| `-i` | 采集间隔（秒） | `5` |
| `-c` | 配置文件路径 | 自动搜索（见下文） |
| `-f` | 写入文件（替代 UDP） | — |
| `-v` | 详细输出 | 关闭 |

Agent 启动时按以下路径搜索配置文件：`config/agent.conf` → `agent/config/agent.conf` → `/etc/tracefox/agent.conf`。可用 `-c <path>` 显式指定（指定路径不存在时直接退出）。配置优先级：

1. 命令行参数（最高）
2. 配置文件
3. 内置默认值（最低）

启动时会打印实际加载的配置路径；`-v` 模式下打印所有生效值。

### 4. 查看大盘

打开 `http://<IP>:3000`，预制的 **TraceFox Server Status** 大盘包含：

- System Uptime / CPU / Memory / Load / Disk Util 仪表盘
- CPU 分解趋势（user/system/iowait/irq）
- RAM 分解（used/buffers+cache/free 堆叠）
- 网络吞吐量（收/发，正/负轴）
- 磁盘延迟（await ms）
- RAM 使用量 + 24h 线性预测
- 进程组表格（按 RSS 排序）

支持 Host / Device / Interface 变量筛选和自定义时间范围。

## 调试工具

不需要完整 VM+Grafana 栈时，可以使用轻量调试服务器：

```bash
cd server
python3 test_server.py              # 终端打印解析后的帧
```

## 告警规则

预配置的 Grafana 告警（`grafana/provisioning/alerting/rules.yml`）：

| 规则 | 条件 | 持续时间 |
|------|------|----------|
| CPU 使用率过高 | user + system > 90% | 5 分钟 |
| 内存使用率过高 | used_pct > 90% | 5 分钟 |
| 磁盘 I/O 利用率高 | io_util > 85% | 5 分钟 |
| 文件系统接近满 | fs_used > 92% | 10 分钟 |
| Agent 离线 | 无数据 | 2 分钟 |

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `TRACEFOX_HOST_LABEL` | 附加到所有指标的 host 标签 | 自动（反向 DNS） |
| `TRACEFOX_UDP_PORT` | UDP 监听端口 | `9000` |
| `TRACEFOX_VM_URL` | VictoriaMetrics 地址 | `http://127.0.0.1:8428` |
| `TRACEFOX_VERBOSE` | 详细日志（`0`/`1`） | `0` |
| `TRACEFOX_QUEUE_SIZE` | Forwarder 内部队列大小 | `1000` |
| `GRAFANA_PASSWORD` | Grafana admin 密码 | `tracefox`（请修改） |

## 参与贡献

欢迎对 TraceFox 提出改进和修复。详细信息请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 指标列表

所有指标以 `tracefox_` 为前缀，主要标签：`host`、`device`、`interface`、`mount`、`group`。

| 指标 | 类型 | 说明 |
|------|------|------|
| `tracefox_up` | Gauge | Agent 心跳（始终为 1） |
| `tracefox_uptime_seconds` | Gauge | Forwarder 首次收到该 host 数据至今的秒数 |
| `tracefox_cpu_user_pct` | Gauge | CPU 用户态百分比 |
| `tracefox_cpu_system_pct` | Gauge | CPU 内核态百分比 |
| `tracefox_cpu_idle_pct` | Gauge | CPU 空闲百分比 |
| `tracefox_cpu_iowait_pct` | Gauge | CPU I/O 等待百分比 |
| `tracefox_cpu_irq_pct` | Gauge | CPU 中断百分比 |
| `tracefox_mem_total_kb` | Gauge | 总内存（KB） |
| `tracefox_mem_free_kb` | Gauge | 空闲内存（KB） |
| `tracefox_mem_available_kb` | Gauge | 可用内存（KB） |
| `tracefox_mem_used_kb` | Gauge | 已用内存（KB，基于 MemAvailable） |
| `tracefox_mem_used_pct` | Gauge | 内存使用率（%，基于 MemAvailable） |
| `tracefox_load_1m` | Gauge | 1 分钟负载均值 |
| `tracefox_load_5m` | Gauge | 5 分钟负载均值 |
| `tracefox_load_15m` | Gauge | 15 分钟负载均值 |
| `tracefox_net_rx_bytes_total` | Counter | 网络接口接收字节数（累计） |
| `tracefox_net_tx_bytes_total` | Counter | 网络接口发送字节数（累计） |
| `tracefox_disk_reads_completed_total` | Counter | 磁盘读完成次数（累计） |
| `tracefox_disk_writes_completed_total` | Counter | 磁盘写完成次数（累计） |
| `tracefox_disk_read_iops` | Gauge | 读 IOPS（区间增量） |
| `tracefox_disk_write_iops` | Gauge | 写 IOPS（区间增量） |
| `tracefox_disk_io_util_pct` | Gauge | 磁盘 I/O 利用率（%） |
| `tracefox_fs_total_kb` | Gauge | 文件系统总容量（KB） |
| `tracefox_fs_used_pct` | Gauge | 文件系统使用率（%） |
| `tracefox_proc_instances` | Gauge | 进程组实例数 |
| `tracefox_proc_cpu_pct` | Gauge | 进程组 CPU 使用率（%） |
| `tracefox_proc_rss_kb` | Gauge | 进程组 RSS 总和（KB） |

## 部署说明

- 所有服务使用 `network_mode: host`，直接使用宿主机网络
- VictoriaMetrics 监听 `:8428`，Grafana 监听 `:3000`，Forwarder 监听 UDP `:9000`
- **安全建议**：生产环境部署前务必修改 `.env` 中的 `GRAFANA_PASSWORD`
- 镜像版本已固定（VictoriaMetrics `v1.106.1`、Grafana `11.4.0`），避免 `:latest` 带来的不可预期升级
- Grafana 匿名访问默认关闭，需登录后使用
- 磁盘累计计数器使用 64 位，支持长时间运行和大容量设备
- 文件系统使用率基于 `f_bavail`（普通用户可用空间），与 `df` 一致
