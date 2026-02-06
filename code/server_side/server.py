import socket
import os
import csv
from datetime import datetime
import sys
from crypto_utils import chunk_bytes, merkle_root  # <-- added these

# ────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────

HOST = "0.0.0.0"
PORT = 4455

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "received_files")
LOG_FILE = os.path.join(BASE_DIR, "logs.csv")

os.makedirs(DATA_DIR, exist_ok=True)

# ────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────

def recvall(conn, n):
    data = b""
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            raise ConnectionError("Client disconnected")
        data += part
    return data


def log(event, addr, filename="-", status="-"):
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            addr,
            event,
            filename,
            status
        ])

# ────────────────────────────────────────────────
# Upload Handler
# ────────────────────────────────────────────────

def handle_upload(conn, addr):
    try:
        # filename
        name_len = int.from_bytes(recvall(conn, 4), "big")
        filename = recvall(conn, name_len).decode("utf-8").strip()

        # encrypted file
        data_len = int.from_bytes(recvall(conn, 8), "big")
        encrypted = recvall(conn, data_len)

        # merkle root (ignored by server)
        _ = recvall(conn, 64)

        path = os.path.join(DATA_DIR, filename)
        with open(path, "wb") as f:
            f.write(encrypted)

        conn.sendall(b"VERIFIED")
        log("UPLOAD", addr, filename, "OK")
        print(f"[UPLOAD] {filename} saved")

    except Exception as e:
        print(f"[UPLOAD ERROR] {addr} -> {e}")
        try:
            conn.sendall(b"ERROR")
        except:
            pass
        log("UPLOAD", addr, "-", "ERROR")

# ────────────────────────────────────────────────
# Download Handler (FIXED)
# ────────────────────────────────────────────────

def handle_download(conn, addr):
    try:
        name_len = int.from_bytes(recvall(conn, 4), "big")
        filename = recvall(conn, name_len).decode("utf-8").strip()

        path = os.path.join(DATA_DIR, filename)

        if not os.path.isfile(path):
            conn.sendall(b"NOT_FOUND")
            log("DOWNLOAD", addr, filename, "NOT_FOUND")
            print(f"[NOT FOUND] {filename}")
            return

        conn.sendall(b"FOUND")

        with open(path, "rb") as f:
            encrypted = f.read()

        # send encrypted data
        conn.sendall(len(encrypted).to_bytes(8, "big"))
        conn.sendall(encrypted)

        # ── FIXED ── compute and send actual Merkle root
        chunks = chunk_bytes(encrypted)
        root_hash = merkle_root(chunks).encode("ascii")
        conn.sendall(root_hash)

        log("DOWNLOAD", addr, filename, "OK")
        print(f"[DOWNLOAD] {filename} sent")

    except Exception as e:
        print(f"[DOWNLOAD ERROR] {addr} -> {e}")
        try:
            conn.sendall(b"ERROR")
        except:
            pass
        log("DOWNLOAD", addr, "-", "ERROR")

# ────────────────────────────────────────────────
# Main Server
# ────────────────────────────────────────────────

def main():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(
                ["Time", "Client", "Event", "Filename", "Status"]
            )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1.0)   # allows Ctrl+C to work
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[SERVER] Listening on {HOST}:{PORT}")

    try:
        while True:
            try:
                conn, addr_tuple = server.accept()
            except socket.timeout:
                continue

            addr = f"{addr_tuple[0]}:{addr_tuple[1]}"
            print(f"[NEW CONNECTION] {addr}")

            try:
                cmd = recvall(conn, 10).decode("ascii").strip()
                print(f"[COMMAND] {cmd}")

                if cmd == "UPLOAD":
                    handle_upload(conn, addr)
                elif cmd == "DOWNLOAD":
                    handle_download(conn, addr)
                else:
                    conn.sendall(b"UNKNOWN_CMD")
                    print("[UNKNOWN COMMAND]")

            finally:
                conn.close()

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down")

    finally:
        server.close()

# ────────────────────────────────────────────────

if __name__ == "__main__":
    main()
