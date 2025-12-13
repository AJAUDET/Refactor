# messaging.py — Secure File Transfer with Per-User Ports + Input Lock

import threading
import os
import json
import socket
import struct
import time
from base64 import b64encode, b64decode

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

from network import get_online_users, get_user_ip, get_user_port

# GLOBAL LOCK TO PREVENT CLI FROM STEALING INPUT
input_lock = threading.Lock()

SLEEP_INTERVAL = 0.5 # seconds

# ----------------------------
# JSON helpers
# ----------------------------

def _send_json(sock, obj):
    data = json.dumps(obj).encode()
    header = struct.pack("!I", len(data))
    time.sleep(SLEEP_INTERVAL) # Quick sleep to avoid TCP packet merging
    sock.sendall(header + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf


def _recv_json(sock):
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    data = _recv_exact(sock, length)
    return json.loads(data.decode())


# ----------------------------
# Key helpers
# ----------------------------

PASSWD_FILE = "passwd.json"
PRIVATE_KEY_DIR = "private_keys"


def _load_recipient_public_key(recipient):
    with open(PASSWD_FILE, "r") as f:
        data = json.load(f)

    pub = data["Users"][recipient]["Public Key"]
    return RSA.import_key(pub.encode())


def _load_private_key(username):
    with open(os.path.join(PRIVATE_KEY_DIR, f"{username}.priv"), "rb") as f:
        return RSA.import_key(f.read())


# ----------------------------
# Crypto
# ----------------------------

def _encrypt_file_for_recipient(recipient, filepath):
    pub = _load_recipient_public_key(recipient)

    with open(filepath, "rb") as f:
        plaintext = f.read()

    session_key = get_random_bytes(16)
    rsa_cipher = PKCS1_OAEP.new(pub)
    encrypted_sk = rsa_cipher.encrypt(session_key)

    aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(plaintext)

    return {
        "encrypted_session_key": b64encode(encrypted_sk).decode(),
        "nonce": b64encode(aes.nonce).decode(),
        "tag": b64encode(tag).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
    }


def _decrypt_file(username, packet):
    priv = _load_private_key(username)

    encrypted_sk = b64decode(packet["encrypted_session_key"])
    nonce = b64decode(packet["nonce"])
    tag = b64decode(packet["tag"])
    ciphertext = b64decode(packet["ciphertext"])

    sk = PKCS1_OAEP.new(priv).decrypt(encrypted_sk)
    aes = AES.new(sk, AES.MODE_GCM, nonce)
    return aes.decrypt_and_verify(ciphertext, tag)


# ----------------------------
# Sender
# ----------------------------

def send_file_command(username, *args):
    if len(args) != 2:
        print("Usage: send <user> <file>")
        return

    recipient, filepath = args

    if not os.path.isfile(filepath):
        print("[ERROR] File not found:", filepath)
        return

    if recipient not in get_online_users():
        print(f"[WARN] '{recipient}' is not online.")
        return

    ip = get_user_ip(recipient)
    port = get_user_port(recipient)

    if not ip or not port:
        print("[ERROR] Missing recipient address/port.")
        return

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, port))

        offer = {
            "type": "file_offer",
            "sender": username,
            "recipient": recipient,
            "filename": filename,
            "filesize": filesize,
        }
        _send_json(sock, offer)

        response = _recv_json(sock)
        if response.get("status") != "accepted":
            print("Contact has rejected the transfer request.")
            sock.close()
            return

        print("Contact has accepted the transfer request.")

        enc = _encrypt_file_for_recipient(recipient, filepath)
        enc.update(
            {"type": "file_data", "filename": filename, "filesize": filesize})
        _send_json(sock, enc)

        print("File has been successfully transferred.")
        sock.close()

    except Exception as e:
        print("[ERROR] Failed to send file:", e)


# ----------------------------
# Receiver
# ----------------------------

def _handle_client(conn, addr, username):
    try:
        offer = _recv_json(conn)
        if offer.get("type") != "file_offer":
            return

        sender = offer["sender"]
        filename = offer["filename"]
        filesize = offer["filesize"]

        # Print file offer details
        print(f"\n[FILE] Contact '{sender}' is sending a file:")
        print(f"       Name: {filename}")
        print(f"       Size: {filesize} bytes\n")

        # LOCK THE CLI
        input_lock.acquire()
        try:
            while True:
                choice = input("Accept file? (y/n): ").strip().lower()
                if choice in ("y", "n"):
                    break
        finally:
            input_lock.release()

        if choice != "y":
            _send_json(conn, {"type": "file_response", "status": "rejected"})
            print("[INFO] File transfer rejected.\n")
            return

        _send_json(conn, {"type": "file_response", "status": "accepted"})

        packet = _recv_json(conn)
        if packet.get("type") != "file_data":
            print("[ERROR] Expected file_data.")
            return

        plaintext = _decrypt_file(username, packet)

        save_dir = os.path.join("received_files", username)
        os.makedirs(save_dir, exist_ok=True)
        save_path = os.path.join(save_dir, filename)

        with open(save_path, "wb") as f:
            f.write(plaintext)

        print(f"[INFO] File received and saved to: {save_path}\n")

    finally:
        conn.close()


def _listener_thread(username, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(("", port))
    sock.listen(5)
    print(f"[INFO] File transfer listener running on port {port}.\n")

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=_handle_client,
                         args=(conn, addr, username), daemon=True).start()


def start_file_listener(username, port):
    threading.Thread(target=_listener_thread,
                     args=(username, port), daemon=True).start()
