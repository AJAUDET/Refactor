# network.py
# Tracks online users with last_seen timestamp, IP address, AND per-user TCP port.

import socket
import threading
import json
import time

BROADCAST_PORT = 54545
BUFFER_SIZE = 1024
BROADCAST_INTERVAL = 5
TIMEOUT = 15

# username → {"last_seen", "ip", "port"}
online_users = {}
lock = threading.Lock()


def broadcast_presence(username, user_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        try:
            msg = json.dumps({"user": username, "port": user_port}).encode()
            sock.sendto(msg, ("<broadcast>", BROADCAST_PORT))
        except:
            pass

        time.sleep(BROADCAST_INTERVAL)


def listen_for_users():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", BROADCAST_PORT))

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            msg = json.loads(data.decode())
            user = msg.get("user")
            sender_ip = addr[0]
            sender_port = msg.get("port")

            if user:
                with lock:
                    online_users[user] = {
                        "last_seen": time.time(),
                        "ip": sender_ip,
                        "port": sender_port
                    }
        except:
            continue


def cleanup_offline_users():
    while True:
        time.sleep(5)
        now = time.time()
        with lock:
            dead = [u for u, info in online_users.items()
                    if now - info["last_seen"] > TIMEOUT]
            for u in dead:
                del online_users[u]


def start_network(username, port):
    threading.Thread(target=broadcast_presence,
                     args=(username, port), daemon=True).start()
    threading.Thread(target=listen_for_users, daemon=True).start()
    threading.Thread(target=cleanup_offline_users, daemon=True).start()


def get_online_users():
    with lock:
        return set(online_users.keys())


def get_user_ip(username):
    with lock:
        entry = online_users.get(username)
        return entry["ip"] if entry else None


def get_user_port(username):
    with lock:
        entry = online_users.get(username)
        return entry.get("port") if entry else None
