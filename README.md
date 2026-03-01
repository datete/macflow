# iStoreOS MAC 分流系统（阶段 A+B）

这个仓库先实现最关键的系统级闭环：

- ARM64 固件化前的本地调试基线（WSL2 / Linux）
- MAC 分流（仅策略域设备生效）
- 事务化应用（校验 -> 提交 -> 健康检查 -> 失败回滚）
- DNS 防泄露（53 强制收敛 + DoH/DoQ 阻断占位）

## 目录说明

- `config/policy.example.json`：策略样例（设备、分组、节点、DNS）
- `core/rule-engine/render_policy.py`：把策略渲染为 nft/iprule 产物
- `core/apply/atomic_apply.sh`：原子应用入口（最小扰动）
- `core/apply/device_patch.sh`：设备级差分更新（不全量重载）
- `core/dns/dns_guard.nft`：DNS 防泄露规则模板
- `core/dns/dns_leak_probe.sh`：DNS 泄露主动探针
- `scripts/setup-netns.sh`：本地 netns 拓扑（router/wan/lan）
- `scripts/smoke_test.sh`：基础连通与规则冒烟测试

## 快速开始

1) 准备依赖（Ubuntu/WSL）

```bash
sudo apt update
sudo apt install -y nftables iproute2 jq python3 conntrack iputils-ping
```

2) 启动测试拓扑

```bash
sudo bash scripts/setup-netns.sh up
```

3) 渲染策略

```bash
python3 core/rule-engine/render_policy.py \
  --policy config/policy.example.json \
  --out-dir build
```

4) 原子应用（在 router 命名空间）

```bash
sudo bash core/apply/atomic_apply.sh \
  --nft build/macflow.nft \
  --iprules build/iprules.sh \
  --health-target 10.0.1.2 \
  --policy-version demo-v1 \
  --namespace ns-router
```

4.1) 差分更新单台设备（不影响其他设备）

```bash
sudo bash core/apply/device_patch.sh \
  --action upsert \
  --mac 02:AA:BB:CC:DD:10 \
  --mark 0x100 \
  --namespace ns-router
```

4.2) DNS 泄露探针（结构校验 / 严格校验）

```bash
# 结构校验（默认）
sudo bash core/dns/dns_leak_probe.sh --router-ns ns-router --lan-ns ns-lan

# 严格模式（计数器必须增长）
sudo bash core/dns/dns_leak_probe.sh --router-ns ns-router --lan-ns ns-lan --strict
```

5) 冒烟验证

```bash
sudo bash scripts/smoke_test.sh
```

6) 清理

```bash
sudo bash scripts/setup-netns.sh down
```

## 设计要点

- 非纳管设备不打 mark，不进入策略路由。
- 已有连接依赖 `ct mark` 保持原路径，避免“切换时全网抖动”。
- 应用配置不走全局重启，默认只做局部规则替换。
- 节点异常按 fail-close：仅策略域设备按策略断网。
- 策略应用写入版本索引：`current_version` / `rollback_version`。
- DNS 泄露通过主动探针校验（dns_guard 计数器必须增长）。

## 下一阶段

- 接入 3x-ui 同步模块，自动生成节点池。
- 加入 selector 热切换（避免重启 sing-box）。
- 固件打包（R2S -> R4S -> R5S -> H68K）。

## 本地 Docker 演示（完整页面）

1) 启动

```bash
docker compose up -d --build
```

2) 打开页面

```text
http://localhost:18080
```

3) 你会看到

- 仪表卡片（服务状态、节点数量、设备数量、最后应用时间）
- 3x-ui 同步区（URL/账号/密码 -> 同步节点）
- 设备管理区（按 MAC 加入分组）
- 分组绑定区（把 proxy_hk/proxy_us 绑定具体 outbound tag）
- 策略应用区（应用版本号 + sing-box 配置预览）

4) 停止

```bash
docker compose down
```
