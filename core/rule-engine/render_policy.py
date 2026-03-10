#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys


def fail(msg: str) -> None:
    print(f"[render_policy] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def load_policy(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"policy file not found: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid json: {exc}")


def validate(policy: dict) -> None:
    if "groups" not in policy or "devices" not in policy:
        fail("policy must include groups and devices")

    groups = {g["name"]: g for g in policy["groups"]}
    if "direct" not in groups:
        fail("must define direct group")

    seen_marks = set()
    for g in policy["groups"]:
        mark = int(g["mark"])
        if mark in seen_marks:
            fail(f"duplicate mark found: {mark}")
        seen_marks.add(mark)

    for d in policy["devices"]:
        group = d["group"]
        if group not in groups:
            fail(f"device {d['name']} references unknown group: {group}")


def render_nft(policy: dict) -> str:
    groups = {g["name"]: g for g in policy["groups"]}
    default_mark = int(policy.get("default_mark", 0))
    dns_cfg = policy.get("dns", {})
    dns_port = int(dns_cfg.get("enforce_redirect_port", 6053))
    doh_block_ipv4 = dns_cfg.get("doh_block_ipv4", [])
    doh_block_ipv6 = dns_cfg.get("doh_block_ipv6", [])

    # Default well-known DoH server IPs if none configured
    _DEFAULT_DOH_IPV4 = [
        "1.0.0.1", "1.1.1.1", "8.8.4.4", "8.8.8.8",
        "9.9.9.9", "149.112.112.112",
        "94.140.14.14", "94.140.15.15",
        "208.67.220.220", "208.67.222.222",
    ]
    _DEFAULT_DOH_IPV6 = [
        "2606:4700:4700::1001", "2606:4700:4700::1111",
        "2001:4860:4860::8844", "2001:4860:4860::8888",
        "2620:fe::9", "2620:fe::fe",
    ]

    mac_elements = []
    managed_macs = []
    for d in policy["devices"]:
        if not d.get("managed", False):
            continue
        mark = int(groups[d["group"]]["mark"])
        mac_elements.append(f'      {d["mac"]} : 0x{mark:x}')
        managed_macs.append(f"      {d['mac']}")

    if not managed_macs:
        managed_macs.append("      00:00:00:00:00:00")
        mac_elements.append(f"      00:00:00:00:00:00 : 0x{default_mark:x}")

    doh4_list = doh_block_ipv4 if doh_block_ipv4 else _DEFAULT_DOH_IPV4
    doh6_list = doh_block_ipv6 if doh_block_ipv6 else _DEFAULT_DOH_IPV6
    doh4_elements = ", ".join(doh4_list)
    doh6_elements = ", ".join(doh6_list)
    nl = "\n"
    mac_block = f",{nl}".join(mac_elements)
    managed_block = f",{nl}".join(managed_macs)

    lines = [
        "table inet macflow {",
        "  map mac_to_mark {",
        "    type ether_addr : mark",
        "    elements = {",
        f"      {mac_block}" if len(mac_elements) == 1 else mac_block,
        "    }",
        "  }",
        "",
        "  set managed_macs {",
        "    type ether_addr",
        "    elements = {",
        f"      {managed_block}" if len(managed_macs) == 1 else managed_block,
        "    }",
        "  }",
        "",
        "  set doh_ipv4 {",
        "    type ipv4_addr",
        f"    elements = {{ {doh4_elements} }}",
        "  }",
        "",
        "  set doh_ipv6 {",
        "    type ipv6_addr",
        f"    elements = {{ {doh6_elements} }}",
        "  }",
        "",
        "  chain prerouting_mark {",
        "    type filter hook prerouting priority mangle; policy accept;",
        "    ct mark != 0x0 meta mark set ct mark",
        "    ct state new ether saddr @managed_macs meta mark set ether saddr map @mac_to_mark",
        "    ct state new ct mark set meta mark",
        "  }",
        "",
        "  chain dns_guard {",
        "    type nat hook prerouting priority dstnat; policy accept;",
        f"    meta mark != 0x0 udp dport 53 counter redirect to :{dns_port}",
        f"    meta mark != 0x0 tcp dport 53 counter redirect to :{dns_port}",
        "  }",
        "",
        "  chain forward_guard {",
        "    type filter hook forward priority filter; policy accept;",
        "    meta mark != 0x0 ip daddr @doh_ipv4 tcp dport 443 counter drop",
        "    meta mark != 0x0 ip daddr @doh_ipv4 udp dport 443 counter drop",
        "    meta mark != 0x0 ip6 daddr @doh_ipv6 tcp dport 443 counter drop",
        "    meta mark != 0x0 ip6 daddr @doh_ipv6 udp dport 443 counter drop",
        "    meta mark != 0x0 tcp dport 853 counter drop",
        "    meta mark != 0x0 udp dport 853 counter drop",
        "    meta mark != 0x0 udp dport 8853 counter drop",
        "    meta mark != 0x0 udp dport 784 counter drop",
        "    meta mark != 0x0 udp dport 3478 counter drop",
        "    meta mark != 0x0 udp dport 5349 counter drop",
        "    meta mark != 0x0 tcp dport 3478 counter drop",
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)


def render_rule_manifest(policy: dict) -> dict:
    """Export a manifest of critical nftables rules for automated health comparison."""
    dns_cfg = policy.get("dns", {})
    dns_port = int(dns_cfg.get("enforce_redirect_port", 6053))
    doh_block_ipv4 = dns_cfg.get("doh_block_ipv4", [])
    managed_count = sum(1 for d in policy.get("devices", []) if d.get("managed", False))
    return {
        "table": "inet macflow",
        "expected_chains": [
            "prerouting_mark", "dns_guard", "forward_guard",
        ],
        "critical_rules": [
            {"chain": "dns_guard", "match": "udp dport 53", "action": f"redirect to :{dns_port}"},
            {"chain": "dns_guard", "match": "tcp dport 53", "action": f"redirect to :{dns_port}"},
            {"chain": "forward_guard", "match": "dport 853", "action": "drop"},
            {"chain": "forward_guard", "match": "doh_ipv4.*dport 443", "action": "drop"},
        ],
        "managed_device_count": managed_count,
        "doh_blocked_ips": doh_block_ipv4,
    }


def render_iprules(policy: dict) -> str:
    """Render ip rule/route commands.

    Table assignment: Uses sequential table numbers starting at MARK_TABLE_BASE (100),
    ordered by mark value. This matches the runtime backend (main.py) _mark_to_table()
    allocation scheme. The group's route_table field is used as a hint but the sequential
    assignment takes precedence to ensure consistency.
    """
    MARK_TABLE_BASE = 100

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Remove old macflow rules (idempotent)",
        "while ip -4 rule show | grep -q 'fwmark .* lookup .* # macflow'; do",
        "  rid=$(ip -4 rule show | awk '/# macflow/ {print $1; exit}' | tr -d ':')",
        "  ip -4 rule del pref \"$rid\" || true",
        "done",
        "",
    ]

    # Build sorted list of non-zero marks for sequential table assignment
    proxy_groups = [g for g in policy["groups"] if int(g["mark"]) != 0]
    proxy_groups.sort(key=lambda g: int(g["mark"]))

    pref = 20000
    for idx, g in enumerate(proxy_groups):
        mark = int(g["mark"])
        table = MARK_TABLE_BASE + idx
        lines.append(
            f"ip -4 rule add pref {pref} fwmark 0x{mark:x} lookup {table} # macflow"
        )

        if g["mode"] == "proxy":
            gateway = g.get("tun_gateway", "172.19.0.1")
            lines.append(f"ip -4 route replace table {table} default via {gateway}")
        else:
            lines.append(f"ip -4 route replace table {table} default dev lo")
        pref += 10

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Render policy to nft/iprule outputs.")
    parser.add_argument("--policy", required=True, help="Path to policy JSON")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    args = parser.parse_args()

    policy_path = pathlib.Path(args.policy)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    policy = load_policy(policy_path)
    validate(policy)

    nft_file = out_dir / "macflow.nft"
    iprule_file = out_dir / "iprules.sh"

    nft_file.write_text(render_nft(policy), encoding="utf-8")
    iprule_file.write_text(render_iprules(policy), encoding="utf-8")

    manifest = render_rule_manifest(policy)
    manifest_file = out_dir / "rule_manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[render_policy] generated: {nft_file}")
    print(f"[render_policy] generated: {iprule_file}")
    print(f"[render_policy] generated: {manifest_file}")


if __name__ == "__main__":
    main()
