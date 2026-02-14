import socket
import ssl
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import time
import sys
import re
from crypto_utils import encrypt_data, decrypt_data, compute_hash

HOST = "127.0.0.1"
PORT = 4455

# Set after login
USERNAME = None
PASSWORD = None


def secure_socket():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    cert_path = os.path.join(os.path.dirname(__file__), "cert.pem")
    if not os.path.exists(cert_path):
        raise FileNotFoundError("cert.pem not found")
    context.load_verify_locations(cert_path)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    status_box.insert(tk.END, msg + "\n")
    status_box.see(tk.END)


def try_authenticate(username: str, password: bytes) -> bool:
    try:
        client = secure_socket()
        client.connect((HOST, PORT))
        client.sendall(str(int(time.time())).encode().ljust(16))
        client.sendall(b"LIST".ljust(16))
        client.sendall(len(username.encode()).to_bytes(4, "big"))
        client.sendall(username.encode())
        client.sendall(len(password).to_bytes(4, "big"))
        client.sendall(password)
        resp = client.recv(16).decode("ascii", errors="ignore").strip()
        client.close()
        return resp == "AUTHOK"
    except Exception:
        return False


# ──── Login Dialog ────
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

    result = {"success": False, "username": "", "password": b""}

    def attempt_login():
        u = user_entry.get().strip()
        p = pass_entry.get().encode()

        if not u or not p:
            status_label.config(text="Both username and password required", fg="red")
            return

        status_label.config(text="Checking credentials...", fg="blue")
        login_win.update()

        if try_authenticate(u, p):
            result["success"] = True
            result["username"] = u
            result["password"] = p
            status_label.config(text="Login successful!", fg="green")
            login_win.after(800, login_win.destroy)
        else:
            status_label.config(text="Invalid username or password", fg="red")

    tk.Button(login_win, text="Login", width=15, command=attempt_login).pack(pady=10)
    login_win.bind("<Return>", lambda e: attempt_login())

    login_win.mainloop()
    return result


# ──── Per-user download folder ────
def get_user_download_dir():
    base = "Downloaded"
    user_dir = os.path.join(base, USERNAME)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir


# ──── Auth helper ────
def send_command_and_auth(client, command: bytes):
    client.sendall(str(int(time.time())).encode().ljust(16))
    client.sendall(command.ljust(16))
    client.sendall(len(USERNAME.encode()).to_bytes(4, "big"))
    client.sendall(USERNAME.encode())
    client.sendall(len(PASSWORD).to_bytes(4, "big"))
    client.sendall(PASSWORD)

    resp = client.recv(16).decode("ascii", errors="ignore").strip()
    update_status(f"[AUTH] {resp}")

    if resp != "AUTHOK":
        raise ConnectionError(f"Authentication failed - server said: {resp}")


# ──── Operations ────
def upload_file():
    path = filedialog.askopenfilename()
    if not path:
        return

    try:
        with open(path, "rb") as f:
            data = f.read()
        filename = os.path.basename(path)
        # Sanitize filename client-side too
        filename = re.sub(r'[^\w\.-]', '_', filename).strip('_.-')
        if not filename:
            messagebox.showerror("Invalid filename", "Filename is empty or invalid after sanitization")
            return

        encrypted = encrypt_data(data)
        file_hash = compute_hash(data)

        update_status(f"[INFO] Uploading {filename} ({len(data)} bytes)")

        client = secure_socket()
        client.connect((HOST, PORT))

        send_command_and_auth(client, b"UPLOAD")

        client.sendall(len(filename.encode()).to_bytes(4, "big"))
        client.sendall(filename.encode())
        client.sendall(len(encrypted).to_bytes(8, "big"))
        client.sendall(encrypted)
        client.sendall(file_hash.encode())

        resp = client.recv(16).decode("ascii", errors="ignore").strip()
        update_status(f"[SERVER] {resp}")

        client.close()

        if resp == "OK":
            list_downloaded_files()
            list_server_files()

    except Exception as e:
        messagebox.showerror("Upload Failed", str(e))
        update_status(f"[ERROR] {str(e)}")


def download_file():
    selected = server_listbox.get(tk.ACTIVE)
    if not selected:
        messagebox.showwarning("No selection", "Please select a file first")
        return

    filename = selected

    try:
        update_status(f"[INFO] Downloading {filename}")

        client = secure_socket()
        client.connect((HOST, PORT))

        send_command_and_auth(client, b"DOWNLOAD")

        client.sendall(len(filename.encode()).to_bytes(4, "big"))
        client.sendall(filename.encode())

        status = client.recv(16).decode("ascii", errors="ignore").strip()
        if status != "FOUND":
            update_status(f"[ERROR] Server: {status}")
            client.close()
            return

        enc_len = int.from_bytes(recv_exact(client, 8), "big")
        encrypted = recv_exact(client, enc_len)
        server_hash = recv_exact(client, 64).decode("ascii").strip()

        client.close()

        data = decrypt_data(encrypted)
        if compute_hash(data) != server_hash:
            update_status("[ERROR] Integrity check failed (hash mismatch)")
            return

        user_dir = get_user_download_dir()
        save_path = os.path.join(user_dir, filename)
        with open(save_path, "wb") as f:
            f.write(data)

        update_status(f"[SUCCESS] Saved to {save_path}")
        list_downloaded_files()

    except Exception as e:
        messagebox.showerror("Download Failed", str(e))
        update_status(f"[ERROR] {str(e)}")


def list_server_files():
    server_listbox.delete(0, tk.END)
    try:
        client = secure_socket()
        client.connect((HOST, PORT))

        send_command_and_auth(client, b"LIST")

        size = int.from_bytes(recv_exact(client, 4), "big")
        data = recv_exact(client, size).decode("utf-8", errors="replace")
        client.close()

        files = [f.strip() for f in data.splitlines() if f.strip()]
        for f in files:
            server_listbox.insert(tk.END, f)

        count = len(files)
        update_status(f"[INFO] Server files refreshed ({count} files)")

    except Exception as e:
        update_status(f"[ERROR] List failed: {str(e)}")


def list_downloaded_files():
    downloaded_listbox.delete(0, tk.END)
    user_dir = get_user_download_dir()
    files = [f for f in os.listdir(user_dir) if os.path.isfile(os.path.join(user_dir, f))]
    for f in sorted(files):
        downloaded_listbox.insert(tk.END, f)
    update_status(f"[INFO] Your downloaded files: {len(files)}")


def register_user_gui():
    username = simpledialog.askstring("Register", "Enter new username:")
    if not username or not username.strip():
        return

    password = simpledialog.askstring("Register", "Enter password:", show="*")
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
    if messagebox.askyesno("Logout", f"Log out {USERNAME} and return to login?"):
        root.destroy()
        # Restart script to show login again
        os.execl(sys.executable, sys.executable, *sys.argv)


# ──── Main Flow ────
login_result = show_login_dialog()

if not login_result["success"]:
    messagebox.showinfo("Login Cancelled", "You must log in to use the application.")
    sys.exit()

USERNAME = login_result["username"]
PASSWORD = login_result["password"]


# ──── GUI ────
root = tk.Tk()
root.title(f"Secure File Transfer - {USERNAME}")
root.geometry("800x600")

tk.Label(root, text="Secure File Transfer", font=("Arial", 18, "bold")).pack(pady=5)
tk.Label(root, text=f"Logged in as: {USERNAME}", font=("Arial", 12, "italic"), fg="#555").pack(pady=(0, 10))

tk.Button(root, text="Upload File", width=30, command=upload_file).pack(pady=4)
tk.Button(root, text="Download Selected Server File", width=30, command=download_file).pack(pady=4)
tk.Button(root, text="Register New User", width=30, command=register_user_gui).pack(pady=4)
tk.Button(root, text="Logout", width=30, command=logout, bg="#ff6b6b", fg="white").pack(pady=8)

list_frame = tk.Frame(root)
list_frame.pack(pady=10, fill=tk.BOTH, expand=True)

server_frame = tk.Frame(list_frame)
server_frame.pack(side=tk.LEFT, padx=20, fill=tk.BOTH, expand=True)
tk.Label(server_frame, text="Server Files", font=("Arial", 14, "bold")).pack()
server_listbox = tk.Listbox(server_frame, width=40, height=15)
server_listbox.pack(fill=tk.BOTH, expand=True)
tk.Button(server_frame, text="Refresh Server Files", command=list_server_files).pack(pady=5)

downloaded_frame = tk.Frame(list_frame)
downloaded_frame.pack(side=tk.LEFT, padx=20, fill=tk.BOTH, expand=True)
tk.Label(downloaded_frame, text="Your Downloaded Files", font=("Arial", 14, "bold")).pack()
downloaded_listbox = tk.Listbox(downloaded_frame, width=40, height=15)
downloaded_listbox.pack(fill=tk.BOTH, expand=True)

tk.Label(root, text="Status Log", font=("Arial", 14, "bold")).pack(pady=5)
status_box = tk.Text(root, height=10, width=100)
status_box.pack(padx=10, pady=5, fill=tk.BOTH)

# Initial load + welcome
list_downloaded_files()
list_server_files()
update_status(f"Welcome, {USERNAME}! You are now connected and ready to transfer files. 💾")

root.mainloop()