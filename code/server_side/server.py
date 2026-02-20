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
import secrets
from datetime import datetime, timezone, timedelta

HOST = "0.0.0.0"
PORT = 4455

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
FILE_DIR  = STORAGE_DIR / "files"
HASH_DIR  = STORAGE_DIR / "hashes"
USER_FILE = STORAGE_DIR / "users.json"
LOG_FILE  = STORAGE_DIR / "security.log"

MAX_FILE_SIZE = 100 * 1024 * 1024
TOKEN_VALID_HOURS = 24
TOKEN_LENGTH = 32

for d in [FILE_DIR, HASH_DIR, STORAGE_DIR]:
    os.makedirs(d, exist_ok=True)

active_sessions = {}
sessions_lock = threading.Lock()


def log(msg, level="INFO"):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    prefix = {"INFO": "[INFO]", "WARN": "[WARN]", "ERROR": "[ERROR]", "AUTH": "[AUTH]", "CMD": "[CMD]"}.get(level, "[INFO]")
    full_msg = f"{ts} {prefix} {msg}"
    print(full_msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(full_msg + "\n")


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
        return json.loads(USER_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"users.json invalid: {e}", "WARN")
        salt = os.urandom(16)
        users = {"admin": {"salt": salt.hex(), "hash": hash_password(b"admin123", salt)}}
        USER_FILE.write_text(json.dumps(users, indent=4))
        return users


def create_session_token(username: str) -> str:
    token_bytes = secrets.token_bytes(TOKEN_LENGTH)
    token_hex = token_bytes.hex()
    expiry = datetime.now(timezone.utc) + timedelta(hours=TOKEN_VALID_HOURS)

    with sessions_lock:
        active_sessions[token_hex] = (username, expiry)
        log(f"New session token created for {username} (valid until {expiry.isoformat()})")

    return token_hex


def validate_session_token(token_hex: str) -> tuple[str | None, bool]:
    if not token_hex:
        return None, False

    with sessions_lock:
        if token_hex not in active_sessions:
            return None, False

        username, expiry = active_sessions[token_hex]
        
        if datetime.now(timezone.utc) > expiry:
            del active_sessions[token_hex]
            log(f"Expired session token used for {username}", "WARN")
            return None, False

        return username, True


def cleanup_expired_sessions():
    with sessions_lock:
        now = datetime.now(timezone.utc)
        to_remove = []
        for token, (username, expiry) in list(active_sessions.items()):
            if now > expiry:
                to_remove.append(token)
        
        for token in to_remove:
            del active_sessions[token]
            log(f"Cleaned up expired session: {token[:12]}... for {username}")


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


def register_user(conn):
    users = load_users()
    try:
        ulen = int.from_bytes(recv_exact(conn, 4), 'big')
        username = recv_exact(conn, ulen).decode('utf-8', errors='replace').strip()

        plen = int.from_bytes(recv_exact(conn, 4), 'big')
        password = recv_exact(conn, plen)

        if username in users:
            conn.sendall(b"EXISTS")
            log(f"Register attempted for existing user: {username}")
            return

        if not username or len(username) > 64:
            conn.sendall(b"REGFAIL")
            return

        salt = os.urandom(16)
        users[username] = {"salt": salt.hex(), "hash": hash_password(password, salt)}
        USER_FILE.write_text(json.dumps(users, indent=4))

        conn.sendall(b"REGISTERED")
        log(f"Registered new user: {username}")

    except Exception as e:
        log(f"Register error: {e}", "ERROR")
        conn.sendall(b"REGFAIL")


def handle_login(conn):
    users = load_users()
    try:
        ulen = int.from_bytes(recv_exact(conn, 4), 'big')
        username = recv_exact(conn, ulen).decode('utf-8', errors='replace').strip()

        plen = int.from_bytes(recv_exact(conn, 4), 'big')
        password = recv_exact(conn, plen)

        if username not in users:
            log(f"Login attempt - unknown user: {username}", "AUTH")
            conn.sendall(b"AUTHFAIL")
            return

        stored = users[username]
        if hash_password(password, bytes.fromhex(stored["salt"])) != stored["hash"]:
            log(f"Login failed - wrong password for {username}", "AUTH")
            conn.sendall(b"AUTHFAIL")
            return

        token = create_session_token(username)
        conn.sendall(b"TOKOK")
        conn.sendall(len(token.encode()).to_bytes(4, 'big'))
        conn.sendall(token.encode())

        log(f"Login success → token issued for {username}")

    except Exception as e:
        log(f"Login error: {e}", "ERROR")
        conn.sendall(b"AUTHFAIL")


def handle_delete(conn, username):
    try:
        nlen = int.from_bytes(recv_exact(conn, 4), 'big')
        filename = safe_filename(recv_exact(conn, nlen).decode('utf-8', errors='replace'))

        user_file_dir = FILE_DIR / username
        user_hash_dir = HASH_DIR / username

        file_path = user_file_dir / filename
        hash_path = user_hash_dir / f"{filename}.hash"

        if not file_path.is_file():
            conn.sendall(b"NOTFOUND")
            log(f"Delete failed - file not found: {filename} by {username}", "WARN")
            return

        file_path.unlink()
        if hash_path.is_file():
            hash_path.unlink()

        conn.sendall(b"OK")
        log(f"File deleted: {filename} by {username}")

    except Exception as e:
        log(f"Delete error for {filename} by {username}: {e}", "ERROR")
        conn.sendall(b"DELFAIL")


def integrity_self_check():
    log("Running startup integrity check")
    for user_dir in FILE_DIR.iterdir():
        if not user_dir.is_dir():
            continue
        user_hash_dir = HASH_DIR / user_dir.name
        if not user_hash_dir.is_dir():
            continue

        for file in user_dir.iterdir():
            if not file.is_file():
                continue
            hash_file = user_hash_dir / f"{file.name}.hash"
            if not hash_file.is_file():
                log(f"Missing hash for {file}", "WARN")
                continue

            stored_hash = hash_file.read_text(encoding="utf-8").strip()
            actual_hash = hashlib.sha256(file.read_bytes()).hexdigest()

            if stored_hash != actual_hash:
                log(f"Integrity violation detected: {file}", "ERROR")


def handle_client(conn, addr):
    client = f"{addr[0]}:{addr[1]}"
    log(f"Connection from {client}")

    try:
        ts_bytes = recv_exact(conn, 16).strip()
        try:
            timestamp = int(ts_bytes)
        except ValueError:
            conn.sendall(b"BADTS")
            log(f"Invalid timestamp format from {client}", "WARN")
            return

        now = int(time.time())
        if abs(now - timestamp) > 30:
            conn.sendall(b"REPLAY")
            log(f"Replay detected from {client} (Δt = {abs(now - timestamp)}s)", "WARN")
            return

        cmd = recv_exact(conn, 16).decode('ascii', errors='ignore').strip().upper()
        log(f"Command: {cmd} from {client}")

        if cmd == "REGISTER":
            register_user(conn)
            return

        if cmd == "LOGIN":
            handle_login(conn)
            return

        ulen = int.from_bytes(recv_exact(conn, 4), 'big')
        username = recv_exact(conn, ulen).decode('utf-8', errors='replace').strip()

        tlen = int.from_bytes(recv_exact(conn, 4), 'big')
        token_hex = recv_exact(conn, tlen).decode('ascii', errors='ignore').strip()

        validated_username, valid = validate_session_token(token_hex)
        if not valid or validated_username != username:
            conn.sendall(b"AUTHFAIL")
            log(f"Invalid/expired session token for claimed user {username} from {client}", "AUTH")
            return

        conn.sendall(b"AUTHOK")
        log(f"Session valid for {username}")

        user_file_dir = FILE_DIR / username
        user_hash_dir = HASH_DIR / username
        os.makedirs(user_file_dir, exist_ok=True)
        os.makedirs(user_hash_dir, exist_ok=True)

        log(f"[{cmd}] authenticated as {username}")

        if cmd == "UPLOAD":
            nlen = int.from_bytes(recv_exact(conn, 4), 'big')
            filename = safe_filename(recv_exact(conn, nlen).decode('utf-8', errors='replace'))

            flen = int.from_bytes(recv_exact(conn, 8), 'big')
            if flen > MAX_FILE_SIZE:
                conn.sendall(b"TOOBIG")
                log(f"File too big ({flen} bytes) from {username}", "WARN")
                return

            enc_data = recv_exact(conn, flen)
            file_hash = recv_exact(conn, 64).decode('ascii', errors='ignore').strip()

            server_hash = hashlib.sha256(enc_data).hexdigest()
            if server_hash != file_hash:
                conn.sendall(b"HASHFAIL")
                log(f"Hash mismatch on upload {filename} by {username}", "WARN")
                return

            (user_file_dir / filename).write_bytes(enc_data)
            (user_hash_dir / f"{filename}.hash").write_text(file_hash)

            conn.sendall(b"OK")
            log(f"Uploaded {filename} ({flen:,} bytes) by {username}")

        elif cmd == "LIST":
            files = [f.name for f in user_file_dir.iterdir() if f.is_file()]
            data = "\n".join(files).encode('utf-8')
            conn.sendall(len(data).to_bytes(4, 'big'))
            conn.sendall(data)
            log(f"LIST sent {len(files)} files to {username}")

        elif cmd == "DOWNLOAD":
            nlen = int.from_bytes(recv_exact(conn, 4), 'big')
            filename = safe_filename(recv_exact(conn, nlen).decode('utf-8', errors='replace'))

            fpath = user_file_dir / filename
            hpath = user_hash_dir / f"{filename}.hash"

            if not fpath.is_file() or not hpath.is_file():
                conn.sendall(b"NOTFOUND")
                log(f"File not found: {filename} for {username}", "WARN")
                return

            enc_data = fpath.read_bytes()
            fhash = hpath.read_text(encoding="utf-8").strip()

            conn.sendall(b"FOUND")
            conn.sendall(len(enc_data).to_bytes(8, 'big'))
            conn.sendall(enc_data)
            conn.sendall(fhash.encode('ascii'))

            log(f"Sent {filename} ({len(enc_data):,} bytes) to {username}")

        elif cmd == "DELETE":
            handle_delete(conn, username)

        else:
            conn.sendall(b"INVALID")
            log(f"Unknown command '{cmd}' from {username}", "WARN")

    except Exception as e:
        log(f"Handler error {client}: {type(e).__name__}: {e}", "ERROR")
    finally:
        try:
            conn.close()
        except:
            pass


shutdown_flag = threading.Event()
server_socket = None


def shutdown(sig, frame):
    log("Shutdown requested")
    shutdown_flag.set()
    if server_socket:
        try:
            server_socket.close()
        except:
            pass


def start_server():
    global server_socket

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    cert_path = BASE_DIR / "cert.pem"
    key_path  = BASE_DIR / "key.pem"

    if not cert_path.is_file() or not key_path.is_file():
        log("Missing cert.pem or key.pem → cannot start", "ERROR")
        sys.exit(1)

    ssl_context.load_cert_chain(str(cert_path), str(key_path))

    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ssl_context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE

    integrity_self_check()

    def cleanup_thread():
        while not shutdown_flag.is_set():
            cleanup_expired_sessions()
            time.sleep(600)

    threading.Thread(target=cleanup_thread, daemon=True).start()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    server_socket.settimeout(1.0)

    log(f"Secure server listening on {HOST}:{PORT}")
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while not shutdown_flag.is_set():
        try:
            raw_conn, addr = server_socket.accept()
            conn = ssl_context.wrap_socket(raw_conn, server_side=True)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except OSError:
            break
        except Exception as e:
            log(f"Accept error: {e}", "ERROR")

    log("Server stopped")


if __name__ == "__main__":
    start_server()