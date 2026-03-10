# MACFlow — iStoreOS MAC 分流系统 v3.0

基于 nftables + sing-box 的设备级智能分流系统，运行于 iStoreOS / OpenWrt。Go 重写后端，性能大幅提升。

### 核心能力

- **MAC 分流**：按设备 MAC 地址精准分流，仅策略域设备生效
- **事务化应用**：校验 → 提交 → 健康检查 → 失败自动回滚
- **DNS 防泄露**：53 端口强制收敛 + DoH/DoT/DoQ/DNSCrypt/STUN 阻断
- **API 认证**：SHA-256 密码哈希 + 会话令牌 + IP 限频 + 锁定机制
- **SSE 实时推送**：流量、连接数、系统状态实时推送（2s/10s 间隔）
- **响应式面板**：7 套主题 / 3 字体 / 3 密度 / 移动端底部导航 / 命令面板 / 右键快捷菜单
- **ARM64 固件化**：一键打包 R2S/R4S/R5S/H68K 固件，版本自动注入
- **Go 后端**：gin-gonic，零运行时依赖，约 8.8 MB 单文件二进制

## 目录说明

| 目录/文件 | 说明 |
|-----------|------|
| `backend/main.py` | FastAPI 后端（51+ API、认证、SSE、nftables、sing-box） |
| `web/index.html` | 单页管理面板（仪表盘/节点/设备/访问控制/日志） |
| `web/captive.html` | 未纳管设备劫持页 |
| `config/policy.example.json` | 策略样例（设备、分组、节点、DNS） |
| `core/rule-engine/render_policy.py` | 策略渲染为 nft/iprule 产物 |
| `core/apply/atomic_apply.sh` | 原子应用入口（最小扰动） |
| `core/apply/device_patch.sh` | 设备级差分更新（不全量重载） |
| `core/dns/dns_guard.nft` | DNS 防泄露规则模板 |
| `core/dns/dns_leak_probe.sh` | DNS 泄露主动探针 |
| `scripts/setup-netns.sh` | 本地 netns 拓扑（router/wan/lan） |
| `scripts/smoke_test.sh` | 基础连通与规则冒烟测试 |
| `vm/` | QEMU VM 管理、测试套件、部署脚本 |
| `openwrt/` | ARM64 固件/ipk 打包脚本 |
| `docs/` | 架构文档、集成清单、跨网络方案 |

## 快速开始

### 1. iStoreOS 快速连接（跨网络环境）

```bash
bash vm/quick-connect.sh          # 自动发现入口
bash vm/quick-connect.sh --open   # 自动打开面板
bash vm/quick-connect.sh --ssh    # SSH 连接
bash vm/quick-connect.sh --json   # 机器可读输出
```

高级选项：

```bash
# 指定额外候选地址
ISTORE_HOST=192.168.50.1,10.0.0.1 bash vm/quick-connect.sh

# 使用 Tailscale 同步域名
bash vm/sync-connect-from-tailscale.sh
bash vm/quick-connect.sh --json
```

### 2. 本地测试（Ubuntu/WSL）

```bash
# 安装依赖
sudo apt update && sudo apt install -y nftables iproute2 jq python3 conntrack iputils-ping

# 启动测试拓扑
sudo bash scripts/setup-netns.sh up

# 渲染策略
python3 core/rule-engine/render_policy.py \
  --policy config/policy.example.json --out-dir build

# 原子应用
sudo bash core/apply/atomic_apply.sh \
  --nft build/macflow.nft --iprules build/iprules.sh \
  --health-target 10.0.1.2 --policy-version demo-v1 --namespace ns-router

# 冒烟验证
sudo bash scripts/smoke_test.sh

# 清理
sudo bash scripts/setup-netns.sh down
```

## 设计要点

- 非纳管设备不打 mark，不进入策略路由
- 已有连接依赖 `ct mark` 保持原路径，避免"切换时全网抖动"
- 应用配置不走全局重启，默认只做局部规则替换
- 节点异常按 fail-close：仅策略域设备按策略断网
- 策略应用写入版本索引：`current_version` / `rollback_version`
- DNS 泄露通过主动探针校验（dns_guard 计数器必须增长）
- nftables 原子应用：flush+delete+create 在单次 `nft -f -` 中完成
- br-lan 自动检测：支持 eth0/br-lan/br0 等不同固件网桥名称
- 路由表顺序分配：`_mark_to_table()` 按策略 mark 顺序映射表 100+

## API 认证

面板默认无密码。首次设置密码后自动启用认证：

```bash
# 设置密码（首次）
curl -X POST http://localhost:18080/api/auth/setup \
  -H 'Content-Type: application/json' \
  -d '{"password": "your-password"}'

# 登录获取令牌
curl -X POST http://localhost:18080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"password": "your-password"}'
# 返回: {"token": "xxx", "expires_at": "..."}

# 带令牌访问 API
curl http://localhost:18080/api/status \
  -H 'X-Auth-Token: xxx'
```

安全特性：

| 特性 | 说明 |
|------|------|
| 密码存储 | SHA-256 + 随机盐，存于 `data/auth.json` |
| 会话令牌 | 7 天有效期，最多 50 个并存会话 |
| IP 限频 | 每 IP 每分钟最多 5 次登录，超限锁定 5 分钟 |
| 公开路径 | `/`, `/captive*`, `/api/auth/*`, `/api/captive/status`, `/api/events` |
| 令牌传递 | `X-Auth-Token` 头 / `macflow_token` Cookie / `Bearer` Authorization |

## SSE 实时事件流

面板通过 Server-Sent Events 接收实时数据，无需轮询：

```bash
curl -N http://localhost:18080/api/events?token=xxx
```

| 事件类型 | 间隔 | 数据 |
|----------|------|------|
| `traffic` | 2s | 上下行速率、总流量 |
| `connections` | 2s | 当前连接数、上下行累计 |
| `status` | 2s | 服务状态、节点数、设备数 |
| `sysinfo` | 10s | CPU、内存、负载、运行时间 |

前端自动降级：SSE 断开时回退到轮询模式（3s/30s），重连采用指数退避。

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MACFLOW_CORS_ORIGINS` | `*` | 允许的 CORS 源（生产环境应限制） |
| `MACFLOW_CLASH_API` | `http://127.0.0.1:9090` | Clash API 地址 |
| `MACFLOW_STATE_FILE` | `data/state.json` | 状态文件路径 |

## 下一阶段

- [ ] selector 热切换 — 避免每次切节点重启 sing-box
- [ ] 固件打包 — 完成 R2S / R4S / R5S / H68K 适配
- [ ] WebSocket 双向通信 — 替代 SSE 实现双向控制通道
- [ ] 多语言 i18n — 面板中英文切换
- [ ] 策略导入导出 — JSON 文件一键迁移配置

### ARM64 固件打包（R2S 默认）

```bash
bash openwrt/build-arm64-firmware.sh
# 覆盖机型: OPENWRT_PROFILE=friendlyarm_nanopi-r4s bash openwrt/build-arm64-firmware.sh
```

## 本地 Docker 演示

## 本地 Docker 演示

```bash
docker compose up -d --build   # 启动
open http://localhost:18080    # 访问面板
docker compose down            # 停止
```

面板功能：仪表卡片、3x-ui 同步、设备管理、分组绑定、策略应用、实时流量图、命令面板（Ctrl+K）。

## 前端特性

| 特性 | 说明 |
|------|------|
| 7 套主题 | 跟随系统 + 6 个手动主题 |
| 3 种字体 | 系统/等宽/紧凑，按需切换 |
| 3 种密度 | 舒适/标准/紧凑 |
| 移动端适配 | 底部导航栏（< 960px）、响应式布局 |
| 命令面板 | Ctrl+K 全局搜索与快捷操作 |
| Canvas 拓扑图 | 网络拓扑可视化 |
| 骨架屏加载 | 全局加载条 + 骨架微光动画 |
| 无障碍 | focus-visible 焦点环、语义化标签 |
| 滚动返回顶部 | 浮动按钮（滚动 > 300px 时显示） |

## 许可

MIT
