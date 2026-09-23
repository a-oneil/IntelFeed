#!/usr/bin/env python3
"""Lightweight TCP proxy for forwarding webhook traffic from Docker to LAN hosts.

Docker Desktop for Mac runs containers in a VM that can't reach LAN IPs directly.
This proxy runs on the Mac host and forwards traffic so containers can reach LAN
services via host.docker.internal.

Usage:
    python3 scripts/dev/webhook_proxy.py <listen_port> <lan_host> <lan_port>
    python3 scripts/dev/webhook_proxy.py 10138 192.0.2.10 80

Then use http://host.docker.internal:10138/webhook as your webhook URL.

Multiple targets:
    python3 scripts/dev/webhook_proxy.py 10138 192.0.2.10 80 10139 192.0.2.20 8080
"""

import socket
import sys
import threading


def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        src.close()
        dst.close()


def proxy(local_port, remote_host, remote_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", local_port))
    server.listen(5)
    print(f"  :{local_port} -> {remote_host}:{remote_port}")

    while True:
        client, addr = server.accept()
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((remote_host, remote_port))
        except OSError as e:
            print(f"  Cannot connect to {remote_host}:{remote_port}: {e}")
            client.close()
            continue

        threading.Thread(target=forward, args=(client, remote), daemon=True).start()
        threading.Thread(target=forward, args=(remote, client), daemon=True).start()


def main():
    args = sys.argv[1:]
    if len(args) < 3 or len(args) % 3 != 0:
        print("Usage: webhook_proxy.py <local_port> <remote_host> <remote_port> [...]")
        sys.exit(1)

    print("Webhook proxy running (Ctrl+C to stop):")
    threads = []
    for i in range(0, len(args), 3):
        local_port = int(args[i])
        remote_host = args[i + 1]
        remote_port = int(args[i + 2])
        t = threading.Thread(target=proxy, args=(local_port, remote_host, remote_port), daemon=True)
        t.start()
        threads.append(t)

    try:
        threads[0].join()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
