"""TCP port forwarder: Windows localhost -> iStoreOS VM via wsl+socat bridge"""
import subprocess
import socket
import threading
import sys
import time

FORWARDS = [
    (8888, 9080, "iStoreOS LuCI"),
    (18888, 9180, "macflow Panel"),
]

def ensure_wsl_relay():
    """Start socat relays inside WSL if not running."""
    check = subprocess.run(
        ["wsl", "-d", "Ubuntu", "--", "bash", "-c", "pgrep -a socat | grep -c TCP-LISTEN"],
        capture_output=True, text=True
    )
    count = int(check.stdout.strip()) if check.stdout.strip().isdigit() else 0
    if count >= len(FORWARDS):
        return
    print("  Starting WSL socat relays...")
    subprocess.run(
        ["wsl", "-d", "Ubuntu", "--", "bash", "-c",
         "pkill -f 'socat.*TCP-LISTEN' 2>/dev/null; sleep 1; "
         "socat TCP-LISTEN:9080,fork,reuseaddr TCP:127.0.0.1:8080 & "
         "socat TCP-LISTEN:9180,fork,reuseaddr TCP:127.0.0.1:18080 & "
         "sleep 1; echo relays_started"],
        capture_output=True, text=True
    )

def get_wsl_ip():
    r = subprocess.run(
        ["wsl", "-d", "Ubuntu", "--", "bash", "-c",
         "ip -4 addr show eth0 | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}'"],
        capture_output=True, text=True
    )
    ip = r.stdout.strip()
    if not ip:
        raise RuntimeError("Cannot determine WSL2 IP")
    return ip

def pipe(src, dst):
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

def handle_client(client_sock, wsl_ip, wsl_port):
    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(5)
        remote.connect((wsl_ip, wsl_port))
        remote.settimeout(None)
    except Exception as e:
        print(f"  [!] connect failed {wsl_ip}:{wsl_port}: {e}")
        client_sock.close()
        return
    t1 = threading.Thread(target=pipe, args=(client_sock, remote), daemon=True)
    t2 = threading.Thread(target=pipe, args=(remote, client_sock), daemon=True)
    t1.start()
    t2.start()

def start_listener(local_port, wsl_ip, wsl_port, label):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", local_port))
    srv.listen(32)
    print(f"  [ok] localhost:{local_port} -> {wsl_ip}:{wsl_port} ({label})")
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle_client, args=(client, wsl_ip, wsl_port), daemon=True).start()

def main():
    ensure_wsl_relay()
    wsl_ip = get_wsl_ip()
    print(f"\nWindows -> iStoreOS port forwarder (WSL IP: {wsl_ip})")
    print(f"  LuCI:  http://localhost:8888")
    print(f"  Panel: http://localhost:18888")
    print(f"  Ctrl+C to stop\n")

    threads = []
    for local_port, wsl_port, label in FORWARDS:
        t = threading.Thread(target=start_listener, args=(local_port, wsl_ip, wsl_port, label), daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping...")

if __name__ == "__main__":
    main()
