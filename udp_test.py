import socket
import threading
import time

UDP_PORT = 5000
BROADCAST_IP = '<broadcast>'  # This will use the network broadcast automatically
USERNAME = input("Enter a name for this device: ").strip()

def listener():
    """Listen for incoming UDP messages."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', UDP_PORT))
    print(f"[LISTENER] Listening on UDP port {UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(1024)
        print(f"[RECEIVED] From {addr}: {data.decode()}")

def broadcaster():
    """Broadcast a message every 5 seconds."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        message = f"Hello from {USERNAME}"
        sock.sendto(message.encode(), ('255.255.255.255', UDP_PORT))
        print(f"[BROADCAST] Sent: {message}")
        time.sleep(5)

if __name__ == "__main__":
    t1 = threading.Thread(target=listener, daemon=True)
    t2 = threading.Thread(target=broadcaster, daemon=True)

    t1.start()
    t2.start()

    print("UDP broadcast test running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting...")