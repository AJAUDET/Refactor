#Author : Lourenco DaSilva (dslourenco22)
#Purpose : Network module to broadcast and listen for online users in the local network
#ALT : Basis for user presence detection in Secure Drop

import socket
import threading
import json
import time

BROADCAST_PORT = 54545
BUFFER_SIZE = 1024
BROADCAST_INTERVAL = 5
TIMEOUT = 15  
online_users = {}
lock = threading.Lock()

def broadcast_presence(username):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = json.dumps({"user": username}).encode()
    while True:
        try:
            sock.sendto(message, ("<broadcast>", BROADCAST_PORT))
        except Exception:
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
            data, _ = sock.recvfrom(BUFFER_SIZE)
            msg = json.loads(data.decode())
            user = msg.get("user")
            if user:
                with lock:
                    online_users[user] = time.time()
        except Exception:
            continue

def cleanup_offline_users():
    while True:
        time.sleep(5)
        now = time.time()
        with lock:
            to_remove = [user for user, last_seen in online_users.items()
                         if now - last_seen > TIMEOUT]
            for user in to_remove:
                del online_users[user]

def start_network(username):
    threading.Thread(target=broadcast_presence, args=(username,), daemon=True).start()
    threading.Thread(target=listen_for_users, daemon=True).start()
    threading.Thread(target=cleanup_offline_users, daemon=True).start()

def get_online_users():
    with lock:
        return set(online_users.keys())
