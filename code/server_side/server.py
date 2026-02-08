import socket
import os
import signal
import sys
import re
from pathlib import Path
import threading
import ssl
import json
import hashlib
import time

HOST = "0.0.0.0"
PORT = 4455

BASE_DIR = Path(__file__).resolve().parent
FILE_DIR = BASE_DIR / "storage" / "files"
HASH_DIR = BASE_DIR / "storage" / "hashes"
USER_FILE = BASE_DIR / "storage" / "users.json"

MAX_FILE_SIZE = 100 * 1024 * 1024

os.makedirs(FILE_DIR, exist_ok=True)
os.makedirs(HASH_DIR, exist_ok=True)

if not USER_FILE.exists():
    USER_FILE.write_text(json.dumps({
        "admin": hashlib.sha256(b"admin123").hexdigest()
    }))


def safe_filename(name: str) -> str:
    name = re.sub(r'[^\w\.-]', '_', name)
    name = name.strip('_.-')
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


def authenticate(conn):
    user_len = int.from_bytes(recv_exact(conn, 4), "big")
    username = recv_exact(conn, user_len).decode()

    pass_len = int.from_bytes(recv_exact(conn, 4), "big")
    password = recv_exact(conn, pass_len)

    users = json.loads(USER_FILE.read_text())

    if username not in users:
        conn.sendall(b"AUTHFAIL")
        return False

    if hashlib.sha256(password).hexdigest() != users[username]:
        conn.sendall(b"AUTHFAIL")
        return False

    conn.sendall(b"AUTHOK")
    return True


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr[0]}:{addr[1]}")

    try:
        timestamp = int(recv_exact(conn, 16).decode().strip())
        if abs(time.time() - timestamp) > 30:
            conn.sendall(b"REPLAY")
            return

        if not authenticate(conn):
            return

        raw = recv_exact(conn, 16).decode().strip()
        command = raw.upper()

        print(f"[COMMAND] {command}")

        if command == "UPLOAD":
            name_len = int.from_bytes(recv_exact(conn, 4), "big")
            filename = recv_exact(conn, name_len).decode()
            filename = safe_filename(filename)

            file_len = int.from_bytes(recv_exact(conn, 8), "big")
            if file_len > MAX_FILE_SIZE:
                conn.sendall(b"TOOBIG")
                return

            encrypted_data = recv_exact(conn, file_len)
            file_hash = recv_exact(conn, 64).decode()

            (FILE_DIR / filename).write_bytes(encrypted_data)
            (HASH_DIR / f"{filename}.hash").write_text(file_hash)

            conn.sendall(b"OK")

        elif command == "LIST":
            files = os.listdir(FILE_DIR)
            data = "\n".join(files).encode()
            conn.sendall(len(data).to_bytes(4, "big"))
            conn.sendall(data)

        elif command == "DOWNLOAD":
            name_len = int.from_bytes(recv_exact(conn, 4), "big")
            filename = recv_exact(conn, name_len).decode()
            filename = safe_filename(filename)

            file_path = FILE_DIR / filename
            hash_path = HASH_DIR / f"{filename}.hash"

            if not file_path.exists():
                conn.sendall(b"NOTFOUND")
                return

            conn.sendall(b"FOUND")
            encrypted_data = file_path.read_bytes()
            file_hash = hash_path.read_text()

            conn.sendall(len(encrypted_data).to_bytes(8, "big"))
            conn.sendall(encrypted_data)
            conn.sendall(file_hash.encode())

        else:
            conn.sendall(b"INVALID")

    except Exception as e:
        print(f"[ERROR] {e}")
        try:
            conn.sendall(b"ERROR")
        except:
            pass
    finally:
        conn.close()


shutdown_flag = threading.Event()
server_socket = None


def shutdown_server(sig, frame):
    print("\n[SHUTDOWN REQUEST]")
    shutdown_flag.set()
    if server_socket:
        server_socket.close()


def start_server():
    global server_socket

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(str(BASE_DIR / "cert.pem"), str(BASE_DIR / "key.pem"))


    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    server_socket.settimeout(1.0)

    print(f"[SERVER STARTED] Secure server on {HOST}:{PORT}")
    signal.signal(signal.SIGINT, shutdown_server)

    while not shutdown_flag.is_set():
        try:
            raw_conn, addr = server_socket.accept()
            conn = ssl_context.wrap_socket(raw_conn, server_side=True)
            conn.settimeout(60)

            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            ).start()

        except socket.timeout:
            continue
        except OSError:
            break

    print("[SERVER SHUTDOWN COMPLETE]")


if __name__ == "__main__":
    start_server()
