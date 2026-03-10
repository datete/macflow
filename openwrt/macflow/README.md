# macflow OpenWrt/iStoreOS package layout

This directory provides a package skeleton for OpenWrt/iStoreOS.

## Included pieces

- `Makefile`: package definition, dependencies, install paths, upgrade hooks
- `files/etc/init.d/macflow`: procd service (uvicorn + env wiring)
- `files/etc/config/macflow`: runtime options (`app_root`, `data_dir`, `clash_api`, port)
- `files/etc/hotplug.d/iface/99-macflow`: auto re-apply on `wan/wan6 ifup`
- `files/usr/libexec/macflow/upgrade.sh`: state backup/restore for package upgrade
- `files/usr/bin/macflow-selfcheck`: CLI one-click self-check (`quick|full`)
- `files/usr/lib/lua/luci/controller/macflow.lua`: LuCI menu + self-check API
- `files/usr/lib/lua/luci/view/macflow/selfcheck.htm`: LuCI self-check page

## Runtime layout on target

- App root: `/opt/macflow`
- Backend: `/opt/macflow/backend`
- Web: `/opt/macflow/web`
- Data: `/opt/macflow/data`
- Tests: `/opt/macflow/vm/*.sh`

## Build notes

`Makefile` first looks for staged sources under:

- `MACFLOW_SRC_DIR=$(CURDIR)/src`

Then it falls back to monorepo layout:

- `$(CURDIR)/../..`

If your OpenWrt tree stores this package elsewhere, override it:

```bash
make package/macflow/compile V=s MACFLOW_SRC_DIR=/absolute/path/to/macflow/repo
```

## Post-install checklist on router

```bash
/etc/init.d/macflow enable
/etc/init.d/macflow restart
wget -qO- http://127.0.0.1:18080/api/status
/usr/bin/macflow-selfcheck quick
```

## Run from SD card / external storage (R2S recommended)

If your root overlay space is small, keep package install flow unchanged, then move runtime files to an external mount.

1) Make sure storage is mounted and writable (for example `/mnt/mmcblk0p1`):

```bash
mount | grep -E '/mnt|/overlay'
```

2) Run migration helper shipped with the package:

```bash
sh /opt/macflow/scripts/macflow-extstorage.sh status
sh /opt/macflow/scripts/macflow-extstorage.sh migrate /mnt/mmcblk0p1
```

3) Verify service and active runtime path:

```bash
uci get macflow.main.app_root
uci get macflow.main.data_dir
wget -qO- http://127.0.0.1:18080/api/status
```

Notes:

- Upgrade hooks read `macflow.main.app_root` and `macflow.main.data_dir`, so upgrades keep working after migration.
- If external storage is missing during boot, init script falls back to `/opt/macflow` to avoid a hard failure.

## Regression commands (target side)

```bash
cd /opt/macflow
bash vm/run-all-tests.sh
MACFLOW_LONG_TESTS=1 bash vm/run-all-tests.sh

# Or via wrapper
macflow-selfcheck quick
macflow-selfcheck full
```

## LuCI entry

- Path: `系统后台 -> 服务 -> MACFlow -> Self Check`
- `一键快速自检`: runs `final-check.sh`
- `全量回归自检`: runs `MACFLOW_LONG_TESTS=1 run-all-tests.sh`
