import socket
import os
import signal
import sys
import re
from pathlib import Path
import threading
from dotenv import load_dotenv

load_dotenv()

HOST = "0.0.0.0"
PORT = 4455

BASE_DIR = Path(__file__).resolve().parent
FILE_DIR = BASE_DIR / "storage" / "files"
HASH_DIR = BASE_DIR / "storage" / "hashes"


MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB limit

os.makedirs(FILE_DIR, exist_ok=True)
os.makedirs(HASH_DIR, exist_ok=True)



def safe_filename(name: str) -> str:
    name = re.sub(r'[^\w\.-]', '_', name)  # Keep alphanumeric, ., -, _
    name = name.strip('_.-')  # No leading/trailing junk
    if not name or name in {'.', '..'}:
        raise ValueError("Invalid filename")
    if len(name) > 200:
        raise ValueError("Filename too long")
    return name


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        packet = sock.recv(size - len(data))
        if not packet:
            raise ConnectionError("Connection closed unexpectedly")
        data += packet
    return data


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr[0]}:{addr[1]}")

    try:
        # Receive command (up to 16 bytes, strip to get actual)
        raw = recv_exact(conn, 16).decode().strip()
        command = raw.upper()

        print(f"[COMMAND] {command}")

        # ───────── UPLOAD ─────────
        if command == "UPLOAD":
            name_len = int.from_bytes(recv_exact(conn, 4), "big")
            filename = recv_exact(conn, name_len).decode()
            filename = safe_filename(filename)

            file_len = int.from_bytes(recv_exact(conn, 8), "big")
            if file_len > MAX_FILE_SIZE:
                conn.sendall(b"TOOBIG")
                print(f"[REJECTED] {filename} too large: {file_len:,} bytes")
                return

            encrypted_data = recv_exact(conn, file_len)

            file_hash = recv_exact(conn, 64).decode()

            file_path = Path(FILE_DIR) / filename
            hash_path = Path(HASH_DIR) / f"{filename}.hash"

            with open(file_path, "wb") as f:
                f.write(encrypted_data)

            with open(hash_path, "w") as h:
                h.write(file_hash)

            conn.sendall(b"OK")
            print(f"[UPLOAD SUCCESS] {filename}")
        
          # ───────── LIST ─────────
        elif command == "LIST":
            files = os.listdir(FILE_DIR)
            files_data = "\n".join(files).encode()
            
            conn.sendall(len(files_data).to_bytes(4, "big"))
            conn.sendall(files_data)

            print("[LIST SENT]")


        # ───────── DOWNLOAD ─────────
        elif command == "DOWNLOAD":
            name_len = int.from_bytes(recv_exact(conn, 4), "big")
            filename = recv_exact(conn, name_len).decode()
            filename = safe_filename(filename)

            file_path = Path(FILE_DIR) / filename
            hash_path = Path(HASH_DIR) / f"{filename}.hash"

            if not file_path.exists():
                conn.sendall(b"NOTFOUND")
                print(f"[DOWNLOAD FAIL] {filename} not found")
                return

            conn.sendall(b"FOUND")

            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            with open(hash_path, "r") as h:
                file_hash = h.read().strip()

            conn.sendall(len(encrypted_data).to_bytes(8, "big"))
            conn.sendall(encrypted_data)
            conn.sendall(file_hash.encode())

            print(f"[DOWNLOAD SUCCESS] {filename}")

        else:
            conn.sendall(b"INVALID")
            print("[UNKNOWN COMMAND]")

    except Exception as e:
        print(f"[ERROR] {e}")
        conn.sendall(b"ERROR")

    finally:
        conn.close()


shutdown_flag = threading.Event()
server_socket = None


def shutdown_server(sig, frame):
    print("\n[SHUTDOWN REQUEST] Ctrl+C received...")
    shutdown_flag.set()
    if server_socket:
        server_socket.close()  # breaks the accept() blocking call
    print("[SHUTDOWN] Socket closed. Waiting for active clients to finish...")


def start_server():
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        server_socket.settimeout(1.0)  # so accept() doesn't block forever during shutdown

        print(f"[SERVER STARTED] Listening on {HOST}:{PORT} (Ctrl+C to stop)")
        signal.signal(signal.SIGINT, shutdown_server)
        # Optional: also handle SIGTERM (useful in containers / systemd)
        signal.signal(signal.SIGTERM, shutdown_server)
        while not shutdown_flag.is_set():
            try:
                conn, addr = server_socket.accept()
                # Optional: set timeout on client connection too
                conn.settimeout(60)  # close idle clients after 60s
                threading.Thread(
                    target=handle_client,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue  # timeout → just check shutdown flag again
            except OSError as e:
                if shutdown_flag.is_set():
                    break
                print(f"[ACCEPT ERROR] {e}")
    except Exception as e:
        print(f"[FATAL] {e}")
    finally:
        if server_socket:
            server_socket.close()
        print("[SERVER SHUTDOWN COMPLETE]")


if __name__ == "__main__":
    start_server()
