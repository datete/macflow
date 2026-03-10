# MACFlow ARM64 固件集成清单（iStoreOS/OpenWrt）

> **v3.0 — Go 原生版**：后端已从 Python (FastAPI) 迁移为 Go 单二进制，零运行时依赖。
> 固件体积减少约 50 MB（无需内置 Python 运行时）。

## 0) 编译 Go 二进制（首次/更新时）

```bash
cd backend-go

# ARM64 路由器 (R2S/R4S/R5S 等)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o macflowd-arm64 ./cmd/macflowd/

# x86_64 VM 测试
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o macflowd-linux-amd64 ./cmd/macflowd/
```

产物：
- `backend-go/macflowd-arm64` (~8.8 MB) — 用于固件打包和实体路由器
- `backend-go/macflowd-linux-amd64` (~9.4 MB) — 用于 QEMU/Hyper-V VM 测试

## 1) 产出 ARM64 ipk

在仓库根目录执行：

```bash
bash openwrt/build-arm64-ipk.sh
```

脚本会自动：
1. 交叉编译 Go ARM64 二进制（如未编译）
2. 下载 OpenWrt SDK
3. 打包为 ipk

默认构建目标：

- Release: `24.10.0`
- Target: `rockchip`
- Subtarget: `armv8`

可通过环境变量覆盖：

```bash
OPENWRT_RELEASE=24.10.0 OPENWRT_TARGET=mediatek OPENWRT_SUBTARGET=filogic bash openwrt/build-arm64-ipk.sh
```

构建完成后，ipk 输出到：

- `dist/ipk/<target>-<subtarget>/macflow_*.ipk`

## 2) 路由器安装

```bash
opkg install /tmp/macflow_*.ipk
/etc/init.d/macflow enable
/etc/init.d/macflow restart
```

确认服务：

```bash
wget -qO- http://127.0.0.1:18080/api/status
```

确认 SSE 推送：

```bash
wget -qO- http://127.0.0.1:18080/api/events 2>&1 | head -20
```

设置面板密码（可选但推荐）：

```bash
curl -X POST http://127.0.0.1:18080/api/auth/setup \
  -H 'Content-Type: application/json' \
  -d '{"password": "your-secure-password"}'
```

### Go 版 vs Python 版 对比

| 指标 | Python 版 (v2.x) | Go 版 (v3.0) |
|---|---|---|
| 运行时依赖 | python3, pip, fastapi, uvicorn, requests, pydantic | **无** |
| 固件增量 | ~60 MB | ~9 MB |
| 启动时间 | 3-5s | <100ms |
| 内存占用 | 40-60 MB | 8-15 MB |
| 进程数 | 多进程 (uvicorn workers) | 单进程 |

### R2S/arm64 兼容建议（存储空间优先）

Go 版仅 ~9 MB，大幅降低了空间压力：

1. **标准安装**：直接 `opkg install`，即使不启用 extroot 也完全够用。
2. **有扩展存储**：安装后可执行运行目录迁移，数据放外置。
3. **固件内置**：推荐方式，直接打包进固件镜像（见下方第 5 节）。

运行目录迁移（推荐长期方案）：

```bash
# 查看可写挂载点与当前配置
sh /opt/macflow/scripts/macflow-extstorage.sh status

# 迁移到 SD 卡挂载点（示例）
sh /opt/macflow/scripts/macflow-extstorage.sh migrate /mnt/mmcblk0p1

# 校验运行路径与服务状态
uci get macflow.main.app_root
uci get macflow.main.data_dir
/etc/init.d/macflow status
wget -qO- http://127.0.0.1:18080/api/status
```

说明：

- 迁移后 `app_root`/`data_dir` 写入 UCI，升级脚本会按新路径做状态备份与恢复。
- 若外置存储在某次启动时未挂载，init 脚本会自动回退到 `/opt/macflow`，避免服务直接失效。

## 3) 安装后一键自检（CLI / LuCI）

- CLI 快速自检：`macflow-selfcheck quick`
- CLI 全量回归：`macflow-selfcheck full`
- LuCI：`服务 -> MACFlow -> Self Check`

## 4) 分流与防泄露验收

在设备侧至少验证：

1. 分流正确：受管设备命中 `mac_to_mark`，未纳管设备不受影响。
2. 热切换不断网：切节点后旧连接不全断，新连接切到新出口。
3. DNS 防泄露：53 强制收敛；DoH/DoT/DoQ/DNSCrypt/STUN 阻断有效。
4. fail-close 生效：注入故障后自动阻断；恢复后自动回绿。

推荐直接执行：

```bash
cd /opt/macflow
MACFLOW_LONG_TESTS=1 bash vm/run-all-tests.sh
```

## 5) 直接打包固件（R2S 默认）

已提供一键脚本：

```bash
bash openwrt/build-arm64-firmware.sh
```

默认参数：

- `OPENWRT_RELEASE=24.10.0`
- `OPENWRT_TARGET=rockchip`
- `OPENWRT_SUBTARGET=armv8`
- `OPENWRT_PROFILE=friendlyarm_nanopi-r2s`
- `OPENWRT_EXTRA_PACKAGES=''`
- `OPENWRT_PACKAGE_ADJUSTMENTS='-nftables-nojson nftables-json'`

产物目录：

- `dist/firmware/rockchip-armv8/friendlyarm_nanopi-r2s/`

提示：

- 脚本默认会移除 `nftables-nojson` 并显式选用 `nftables-json`，避免 `firewall4` 与包依赖发生冲突。

常用覆盖示例：

```bash
# 指定其他机型 profile
OPENWRT_PROFILE=friendlyarm_nanopi-r4s bash openwrt/build-arm64-firmware.sh

# 附加额外包（按需）
OPENWRT_EXTRA_PACKAGES='luci-base luci-app-package-manager' bash openwrt/build-arm64-firmware.sh
```

首次开机后由 init.d 自动启动，wan/wan6 ifup 时 hotplug 自动重应用策略。
