import socket
import os
import signal
import sys
from hashlib import sha256

HOST = "0.0.0.0"
PORT = 4455
DATA_DIR = "received_files"

os.makedirs(DATA_DIR, exist_ok=True)

server_socket = None


# ─────────────────────────────────────────────
# Graceful shutdown
# ─────────────────────────────────────────────

def shutdown_server(signum=None, frame=None):
    print("\n[!] Server shutting down gracefully...")
    if server_socket:
        server_socket.close()
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown_server)    # Ctrl+C
signal.signal(signal.SIGTERM, shutdown_server)

# Ctrl+Z (Unix only)
try:
    signal.signal(signal.SIGTSTP, shutdown_server)
except AttributeError:
    pass


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise RuntimeError("Connection closed")
        data += packet
    return data


def chunk_bytes(data, size=1024):
    return [data[i:i+size] for i in range(0, len(data), size)]


def merkle_root(chunks):
    if not chunks:
        return sha256(b"").hexdigest()

    level = [sha256(c).digest() for c in chunks]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(sha256(left + right).digest())
        level = next_level

    return level[0].hex()


# ─────────────────────────────────────────────
# Server loop
# ─────────────────────────────────────────────

try:
    server_socket = socket.socket()
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"[+] Server listening on port {PORT} (Ctrl+C to stop)")

    while True:
        conn, addr = server_socket.accept()
        print(f"[+] Connection from {addr}")

        try:
            command = recvall(conn, 6)

            # ───────── UPLOAD ─────────
            if command == b"UPLOAD":
                name_len = int.from_bytes(recvall(conn, 4), "big")
                filename = recvall(conn, name_len).decode()

                enc_len = int.from_bytes(recvall(conn, 8), "big")
                encrypted_data = recvall(conn, enc_len)

                client_root = recvall(conn, 64).decode()

                path = os.path.join(DATA_DIR, filename)
                with open(path, "wb") as f:
                    f.write(encrypted_data)

                server_root = merkle_root(chunk_bytes(encrypted_data))

                if server_root == client_root:
                    conn.sendall(b"VERIFIED")
                else:
                    conn.sendall(b"HASH_MISMATCH")

            # ───────── DOWNLOAD ─────────
            elif command == b"DOWNLOAD":
                name_len = int.from_bytes(recvall(conn, 4), "big")
                filename = recvall(conn, name_len).decode()

                path = os.path.join(DATA_DIR, filename)

                if not os.path.exists(path):
                    conn.sendall(b"NOT_FOUND")
                    continue

                conn.sendall(b"FOUND")

                with open(path, "rb") as f:
                    encrypted_data = f.read()

                root = merkle_root(chunk_bytes(encrypted_data))

                conn.sendall(len(encrypted_data).to_bytes(8, "big"))
                conn.sendall(encrypted_data)
                conn.sendall(root.encode())

        except Exception as e:
            print("[-] Client error:", e)

        finally:
            conn.close()

except KeyboardInterrupt:
    shutdown_server()
