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
from datetime import datetime

HOST = "0.0.0.0"
PORT = 4455

BASE_DIR = Path(__file__).resolve().parent
FILE_DIR  = BASE_DIR / "storage" / "files"
HASH_DIR  = BASE_DIR / "storage" / "hashes"
USER_FILE = BASE_DIR / "storage" / "users.json"

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

for d in [FILE_DIR, HASH_DIR, BASE_DIR / "storage"]:
    os.makedirs(d, exist_ok=True)


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prefix = {"INFO": "[INFO]", "WARN": "[WARN]", "ERROR": "[ERROR]", "AUTH": "[AUTH]", "CMD": "[CMD]"}.get(level, "[INFO]")
    print(f"{ts} {prefix} {msg}", file=sys.stderr if level in ("ERROR", "WARN") else sys.stdout)


def hash_password(password: bytes, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac('sha256', password, salt, 100_000).hex()


def load_users():
    if not USER_FILE.exists():
        salt = os.urandom(16)
        users = {"admin": {"salt": salt.hex(), "hash": hash_password(b"admin123", salt)}}
        USER_FILE.write_text(json.dumps(users, indent=4))
        log("Created default admin user")
        return users

    try:
        users = json.loads(USER_FILE.read_text())
        for u, v in users.items():
            if not all(k in v for k in ("salt", "hash")):
                raise ValueError("Malformed user entry")
        return users
    except Exception as e:
        log(f"users.json invalid: {e} → recreating default", "WARN")
        salt = os.urandom(16)
        users = {"admin": {"salt": salt.hex(), "hash": hash_password(b"admin123", salt)}}
        USER_FILE.write_text(json.dumps(users, indent=4))
        return users


def safe_filename(name: str) -> str:
    name = re.sub(r'[^\w\.-]', '_', name).strip('_.-')
    if not name or name in {'.', '..'}:
        raise ValueError("Invalid filename")
    if len(name) > 200:
        raise ValueError("Filename too long")
    return name


def recv_exact(sock, size: int) -> bytes:
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed during receive")
        data += chunk
    return data


def authenticate(conn):
    users = load_users()
    try:
        ulen = int.from_bytes(recv_exact(conn, 4), 'big')
        username = recv_exact(conn, ulen).decode('utf-8', errors='replace').strip()

        plen = int.from_bytes(recv_exact(conn, 4), 'big')
        password = recv_exact(conn, plen)

        if username not in users:
            conn.sendall(b"AUTHFAIL")
            log(f"Unknown user: {username}")
            return False

        stored = users[username]
        if hash_password(password, bytes.fromhex(stored["salt"])) != stored["hash"]:
            conn.sendall(b"AUTHFAIL")
            log(f"Wrong password for {username}")
            return False

        conn.sendall(b"AUTHOK")
        log(f"Auth success: {username}")
        return True
    except Exception as e:
        log(f"Auth error: {e}", "ERROR")
        conn.sendall(b"AUTHFAIL")
        return False


def register_user(conn):
    users = load_users()
    try:
        ulen = int.from_bytes(recv_exact(conn, 4), 'big')
        username = recv_exact(conn, ulen).decode('utf-8', errors='replace').strip()

        plen = int.from_bytes(recv_exact(conn, 4), 'big')
        password = recv_exact(conn, plen)

        if username in users:
            conn.sendall(b"EXISTS")
            return

        salt = os.urandom(16)
        users[username] = {"salt": salt.hex(), "hash": hash_password(password, salt)}
        USER_FILE.write_text(json.dumps(users, indent=4))
        conn.sendall(b"REGISTERED")
        log(f"Registered new user: {username}")
    except Exception as e:
        log(f"Register error: {e}", "ERROR")
        conn.sendall(b"REGFAIL")


def handle_client(conn, addr):
    client = f"{addr[0]}:{addr[1]}"
    log(f"Connection from {client}")

    try:
        # 1. Timestamp
        ts_str = recv_exact(conn, 16).decode('ascii', errors='ignore').strip()
        timestamp = int(ts_str)
        if abs(time.time() - timestamp) > 30:
            conn.sendall(b"REPLAY")
            log(f"Replay detected from {client}")
            return

        # 2. Command
        cmd = recv_exact(conn, 16).decode('ascii', errors='ignore').strip().upper()

        if cmd == "REGISTER":
            register_user(conn)
            return

        if not authenticate(conn):
            return

        log(f"[{cmd}] from {client}")

        if cmd == "UPLOAD":
            nlen = int.from_bytes(recv_exact(conn, 4), 'big')
            fname_raw = recv_exact(conn, nlen).decode('utf-8', errors='replace')
            filename = safe_filename(fname_raw)

            flen = int.from_bytes(recv_exact(conn, 8), 'big')
            if flen > MAX_FILE_SIZE:
                conn.sendall(b"TOOBIG")
                return

            enc_data = recv_exact(conn, flen)
            file_hash = recv_exact(conn, 64).decode('ascii').strip()

            (FILE_DIR / filename).write_bytes(enc_data)
            (HASH_DIR / f"{filename}.hash").write_text(file_hash)

            conn.sendall(b"OK")
            log(f"Uploaded {filename} ({flen} bytes)")

        elif cmd == "LIST":
            files = [f for f in os.listdir(FILE_DIR) if (FILE_DIR / f).is_file()]
            data = "\n".join(files).encode('utf-8')
            conn.sendall(len(data).to_bytes(4, 'big'))
            conn.sendall(data)

        elif cmd == "DOWNLOAD":
            nlen = int.from_bytes(recv_exact(conn, 4), 'big')
            fname_raw = recv_exact(conn, nlen).decode('utf-8', errors='replace')
            filename = safe_filename(fname_raw)

            fpath = FILE_DIR / filename
            hpath = HASH_DIR / f"{filename}.hash"

            if not fpath.is_file() or not hpath.is_file():
                conn.sendall(b"NOTFOUND")
                return

            enc_data = fpath.read_bytes()
            fhash = hpath.read_text('utf-8').strip()

            conn.sendall(b"FOUND")
            conn.sendall(len(enc_data).to_bytes(8, 'big'))
            conn.sendall(enc_data)
            conn.sendall(fhash.encode('ascii'))

        else:
            conn.sendall(b"INVALID")

    except ValueError as ve:
        log(f"Protocol error from {client}: {ve}", "ERROR")
        conn.sendall(b"PROTOERR")
    except Exception as e:
        log(f"Handler error {client}: {type(e).__name__} {e}", "ERROR")
        try:
            conn.sendall(b"ERROR")
        except:
            pass
    finally:
        conn.close()


shutdown_flag = threading.Event()
server_socket = None


def shutdown(sig, frame):
    log("Shutdown requested")
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

    log(f"Server started on port {PORT}")
    signal.signal(signal.SIGINT, shutdown)

    while not shutdown_flag.is_set():
        try:
            raw_conn, addr = server_socket.accept()
            conn = ssl_context.wrap_socket(raw_conn, server_side=True)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except OSError:
            break

    log("Server stopped")


if __name__ == "__main__":
    start_server()