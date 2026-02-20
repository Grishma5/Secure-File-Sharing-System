import socket
import ssl
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import time
import sys
import re
import hashlib
import secrets

# Replace with your actual crypto_utils module
from crypto_utils import encrypt_data, decrypt_data, compute_hash

HOST = "127.0.0.1"
PORT = 4455

# Globals - set after successful login
USERNAME = None
SESSION_TOKEN = None
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


def secure_socket():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    context.options |= ssl.OP_NO_COMPRESSION

    cert_path = os.path.join(os.path.dirname(__file__), "cert.pem")
    if not os.path.exists(cert_path):
        raise FileNotFoundError("cert.pem not found")

    context.load_verify_locations(cert_path)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(25.0)
    return context.wrap_socket(sock, server_hostname=HOST)


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        data += chunk
    return data


def update_status(msg):
    status_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    status_box.see(tk.END)


def try_login_and_get_token(username: str, password: bytes) -> tuple[bool, str | None]:
    try:
        client = secure_socket()
        client.connect((HOST, PORT))
        client.sendall(str(int(time.time())).encode().ljust(16))
        client.sendall(b"LOGIN".ljust(16))
        client.sendall(len(username.encode()).to_bytes(4, "big"))
        client.sendall(username.encode())
        client.sendall(len(password).to_bytes(4, "big"))
        client.sendall(password)

        resp = client.recv(16).decode("ascii", errors="ignore").strip()
        if resp != "TOKOK":
            client.close()
            return False, None

        token_len = int.from_bytes(recv_exact(client, 4), "big")
        token = recv_exact(client, token_len).decode("ascii")
        client.close()
        return True, token

    except Exception as e:
        update_status(f"[LOGIN ERROR] {str(e)}")
        return False, None


def show_login_dialog():
    login_win = tk.Tk()
    login_win.title("Login - Secure File Transfer")
    login_win.geometry("340x220")
    login_win.resizable(False, False)

    tk.Label(login_win, text="Username:", font=("Arial", 11)).pack(pady=(20, 5))
    user_entry = tk.Entry(login_win, width=35)
    user_entry.insert(0, "admin")
    user_entry.pack()

    tk.Label(login_win, text="Password:", font=("Arial", 11)).pack(pady=(15, 5))
    pass_entry = tk.Entry(login_win, width=35, show="*")
    pass_entry.pack()

    status_label = tk.Label(login_win, text="", fg="red", wraplength=300)
    status_label.pack(pady=8)

    result = {"success": False, "username": "", "token": ""}

    def attempt_login():
        u = user_entry.get().strip()
        p = pass_entry.get().encode()
        if not u or not p:
            status_label.config(text="Both username and password required", fg="red")
            return
        status_label.config(text="Authenticating...", fg="blue")
        login_win.update()

        success, token = try_login_and_get_token(u, p)
        if success:
            result["success"] = True
            result["username"] = u
            result["token"] = token
            status_label.config(text="Login successful!", fg="green")
            login_win.after(800, login_win.destroy)
        else:
            status_label.config(text="Invalid credentials or server error", fg="red")

    tk.Button(login_win, text="Login", width=15, command=attempt_login).pack(pady=10)
    login_win.bind("<Return>", lambda e: attempt_login())
    login_win.mainloop()
    return result


def get_user_download_dir():
    base = "Downloaded"
    user_dir = os.path.join(base, USERNAME)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir


def send_command_and_token(client, command: bytes):
    client.sendall(str(int(time.time())).encode().ljust(16))
    client.sendall(command.ljust(16))
    client.sendall(len(USERNAME.encode()).to_bytes(4, "big"))
    client.sendall(USERNAME.encode())
    client.sendall(len(SESSION_TOKEN.encode()).to_bytes(4, "big"))
    client.sendall(SESSION_TOKEN.encode())
    resp = client.recv(16).decode("ascii", errors="ignore").strip()
    if resp != "AUTHOK":
        raise ConnectionError(f"Session invalid - server said: {resp}")


def upload_file():
    path = filedialog.askopenfilename()
    if not path:
        return

    try:
        with open(path, "rb") as f:
            data = f.read()

        if len(data) > MAX_FILE_SIZE:
            messagebox.showerror("File Too Large", "File exceeds 100 MB limit (client check).")
            update_status("[ERROR] Upload aborted - file too large (client-side check)")
            return

        filename = os.path.basename(path)
        filename = re.sub(r'[^\w\.-]', '_', filename).strip('_.-')
        if not filename:
            messagebox.showerror("Invalid filename", "Filename invalid after sanitization")
            return

        encrypted = encrypt_data(data)
        file_hash = compute_hash(encrypted)

        update_status(f"[UPLOAD] {filename} ({len(data):,} → {len(encrypted):,} bytes)")

        client = secure_socket()
        client.connect((HOST, PORT))
        send_command_and_token(client, b"UPLOAD")

        client.sendall(len(filename.encode()).to_bytes(4, "big"))
        client.sendall(filename.encode())
        client.sendall(len(encrypted).to_bytes(8, "big"))
        client.sendall(encrypted)
        client.sendall(file_hash.encode())

        resp = client.recv(16).decode("ascii", errors="ignore").strip()
        client.close()

        if resp == "OK":
            update_status(f"[SUCCESS] Upload completed: {filename}")
            list_downloaded_files()
            list_server_files()
        elif resp == "HASHFAIL":
            messagebox.showerror("Integrity Error", "Server rejected upload (hash mismatch).")
            update_status("[ERROR] Server hash verification failed")
        elif resp == "TOOBIG":
            messagebox.showerror("File Too Large", "Server rejected - exceeds 100MB.")
            update_status("[ERROR] File too large (server)")
        elif resp == "REPLAY":
            messagebox.showerror("Security Alert", "Replay attack detected by server.")
            update_status("[SECURITY] Replay protection triggered")
        else:
            messagebox.showerror("Upload Failed", f"Server: {resp}")
            update_status(f"[ERROR] {resp}")

    except Exception as e:
        messagebox.showerror("Upload Failed", str(e))
        update_status(f"[ERROR] {str(e)}")


def download_file():
    selected = server_listbox.get(tk.ACTIVE)
    if not selected:
        messagebox.showwarning("Selection Required", "Please select a file first")
        return

    filename = selected
    try:
        update_status(f"[DOWNLOAD] Starting: {filename}")

        client = secure_socket()
        client.connect((HOST, PORT))
        send_command_and_token(client, b"DOWNLOAD")
        client.sendall(len(filename.encode()).to_bytes(4, "big"))
        client.sendall(filename.encode())

        status = client.recv(16).decode("ascii", errors="ignore").strip()
        if status == "NOTFOUND":
            messagebox.showerror("Not Found", "File not found on server")
            update_status("[ERROR] File not found")
            client.close()
            return
        elif status != "FOUND":
            update_status(f"[ERROR] Server: {status}")
            client.close()
            return

        enc_len = int.from_bytes(recv_exact(client, 8), "big")
        encrypted = recv_exact(client, enc_len)
        server_hash = recv_exact(client, 64).decode("ascii").strip()
        client.close()

        computed = compute_hash(encrypted)
        if computed != server_hash:
            update_status("[ERROR] Integrity check failed after download")
            messagebox.showerror("Corrupted Download", "File integrity check failed")
            return

        data = decrypt_data(encrypted)

        user_dir = get_user_download_dir()
        save_path = os.path.join(user_dir, filename)
        with open(save_path, "wb") as f:
            f.write(data)

        update_status(f"[SUCCESS] Downloaded & saved: {save_path}")
        list_downloaded_files()

    except Exception as e:
        messagebox.showerror("Download Failed", str(e))
        update_status(f"[ERROR] {str(e)}")


def delete_file():
    selected = server_listbox.get(tk.ACTIVE)
    if not selected:
        messagebox.showwarning("No selection", "Please select a file from Server Files first")
        return

    filename = selected
    if not messagebox.askyesno("Confirm Delete", f"Really delete '{filename}' from the server?\nThis cannot be undone."):
        return

    try:
        update_status(f"[DELETE] Attempting to remove: {filename}")

        client = secure_socket()
        client.connect((HOST, PORT))
        send_command_and_token(client, b"DELETE")
        client.sendall(len(filename.encode()).to_bytes(4, "big"))
        client.sendall(filename.encode())

        resp = client.recv(16).decode("ascii", errors="ignore").strip()
        client.close()

        if resp == "OK":
            update_status(f"[SUCCESS] File deleted: {filename}")
            list_server_files()  # refresh
        elif resp == "NOTFOUND":
            messagebox.showerror("Not Found", f"File '{filename}' does not exist on server")
            update_status("[ERROR] File not found on server")
        elif resp == "REPLAY":
            messagebox.showerror("Security Alert", "Replay attack detected by server")
            update_status("[SECURITY] Replay protection triggered")
        else:
            messagebox.showerror("Delete Failed", f"Server responded: {resp}")
            update_status(f"[ERROR] Delete failed: {resp}")

    except Exception as e:
        messagebox.showerror("Delete Failed", str(e))
        update_status(f"[ERROR] {str(e)}")


def clear_local_downloads():
    user_dir = get_user_download_dir()
    
    if not os.path.exists(user_dir) or not os.listdir(user_dir):
        update_status("[INFO] Local download folder is already empty")
        messagebox.showinfo("Nothing to Clear", "No files found in local downloads folder.")
        return

    if not messagebox.askyesno("Clear Local Files", 
                              f"Delete ALL {len(os.listdir(user_dir))} file(s) in your local Downloaded folder?\n"
                              "This cannot be undone."):
        return

    deleted_count = 0
    for file in os.listdir(user_dir):
        file_path = os.path.join(user_dir, file)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                deleted_count += 1
        except Exception as e:
            update_status(f"[WARNING] Could not delete {file}: {str(e)}")

    list_downloaded_files()
    update_status(f"[CLEAR] Removed {deleted_count} local file(s)")


def list_server_files():
    server_listbox.delete(0, tk.END)
    try:
        client = secure_socket()
        client.connect((HOST, PORT))
        send_command_and_token(client, b"LIST")
        size = int.from_bytes(recv_exact(client, 4), "big")
        data = recv_exact(client, size).decode("utf-8", errors="replace")
        client.close()

        files = [f.strip() for f in data.splitlines() if f.strip()]
        for f in files:
            server_listbox.insert(tk.END, f)
        update_status(f"[INFO] Server files: {len(files)}")
    except Exception as e:
        update_status(f"[ERROR] List failed: {str(e)}")


def list_downloaded_files():
    downloaded_listbox.delete(0, tk.END)
    user_dir = get_user_download_dir()
    files = [f for f in os.listdir(user_dir) if os.path.isfile(os.path.join(user_dir, f))]
    for f in sorted(files):
        downloaded_listbox.insert(tk.END, f)
    update_status(f"[INFO] Local files: {len(files)}")


def register_user_gui():
    username = simpledialog.askstring("Register", "New username:")
    if not username or not username.strip():
        return
    password = simpledialog.askstring("Register", "New password:", show="*")
    if not password:
        return

    try:
        client = secure_socket()
        client.connect((HOST, PORT))
        client.sendall(str(int(time.time())).encode().ljust(16))
        client.sendall(b"REGISTER".ljust(16))
        client.sendall(len(username.encode()).to_bytes(4, "big"))
        client.sendall(username.encode())
        client.sendall(len(password.encode()).to_bytes(4, "big"))
        client.sendall(password.encode())
        resp = client.recv(16).decode("ascii", errors="ignore").strip()
        client.close()

        messagebox.showinfo("Registration", resp)
        update_status(f"[REGISTER] {resp}")
        if resp == "REGISTERED":
            list_server_files()
    except Exception as e:
        messagebox.showerror("Register Failed", str(e))
        update_status(f"[ERROR] {str(e)}")


def logout():
    global USERNAME, SESSION_TOKEN

    if messagebox.askyesno("Logout", f"Log out {USERNAME}?"):
        SESSION_TOKEN = None
        secrets.token_bytes(64)  # small GC pressure

        root.destroy()
        os.execl(sys.executable, sys.executable, *sys.argv)


# ──── Main Flow ────
login_result = show_login_dialog()
if not login_result["success"]:
    messagebox.showinfo("Login Cancelled", "Login required to continue.")
    sys.exit()

USERNAME = login_result["username"]
SESSION_TOKEN = login_result["token"]

# ──── GUI ────
root = tk.Tk()
root.title(f"Secure File Transfer - {USERNAME}")
root.geometry("800x600")

tk.Label(root, text="Secure File Transfer", font=("Arial", 18, "bold")).pack(pady=5)
tk.Label(root, text=f"Logged in as: {USERNAME}", font=("Arial", 12, "italic"), fg="#555").pack(pady=(0, 10))

tk.Button(root, text="Upload File", width=30, command=upload_file).pack(pady=4)
tk.Button(root, text="Download Selected", width=30, command=download_file).pack(pady=4)
tk.Button(root, text="Delete Selected Server File", width=30, command=delete_file, bg="#ff9999", fg="white").pack(pady=4)
tk.Button(root, text="Register New User", width=30, command=register_user_gui).pack(pady=4)
tk.Button(root, text="Clear Local Downloads", width=30, command=clear_local_downloads, bg="#ffcc99").pack(pady=4)
tk.Button(root, text="Logout", width=30, command=logout, bg="#ff6b6b", fg="white").pack(pady=8)

list_frame = tk.Frame(root)
list_frame.pack(pady=10, fill=tk.BOTH, expand=True)

server_frame = tk.Frame(list_frame)
server_frame.pack(side=tk.LEFT, padx=20, fill=tk.BOTH, expand=True)
tk.Label(server_frame, text="Server Files", font=("Arial", 14, "bold")).pack()
server_listbox = tk.Listbox(server_frame, width=40, height=15)
server_listbox.pack(fill=tk.BOTH, expand=True)
tk.Button(server_frame, text="Refresh", command=list_server_files).pack(pady=5)

downloaded_frame = tk.Frame(list_frame)
downloaded_frame.pack(side=tk.LEFT, padx=20, fill=tk.BOTH, expand=True)
tk.Label(downloaded_frame, text="Downloaded Files", font=("Arial", 14, "bold")).pack()
downloaded_listbox = tk.Listbox(downloaded_frame, width=40, height=15)
downloaded_listbox.pack(fill=tk.BOTH, expand=True)

tk.Label(root, text="Status Log", font=("Arial", 14, "bold")).pack(pady=5)
status_box = tk.Text(root, height=10, width=100, font=("Consolas", 10))
status_box.pack(padx=10, pady=5, fill=tk.BOTH)

# Initial load
list_downloaded_files()
list_server_files()
update_status(f"Welcome back, {USERNAME}! Session ready. ✓")

root.mainloop()