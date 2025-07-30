import socket
import threading
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.exceptions import SMBAuthenticationError

# ---------- NetBIOS / SMB Info Function ---------- #
def get_netbios_info(ip):
    try:
        conn = Connection(uuid=None, username="", password="", server=str(ip), port=445)
        conn.connect(timeout=1)  # try to connect to SMB
        session = Session(conn, username="", password="")
        session.connect()
        workgroup = session.session_id  # dummy value
        conn.disconnect()
        return "SMB Active"
    except SMBAuthenticationError:
        return "SMB Auth Required"
    except:
        return "No SMB"

# ---------- Host Scan ---------- #
def scan_host(ip, ports, tree):
    open_ports = []
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
    except:
        hostname = "Unknown"

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass

    if open_ports:
        netbios_info = get_netbios_info(ip)
        tree.insert("", tk.END, values=(str(ip), hostname, netbios_info, ", ".join(map(str, open_ports))))

# ---------- Main Scan Trigger ---------- #
def start_scan(start_ip, end_ip, port_range, tree, scan_btn):
    tree.delete(*tree.get_children())
    scan_btn.config(state=tk.DISABLED)

    try:
        ip_net = ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip))
        all_ips = []
        for block in ip_net:
            for ip in block:
                all_ips.append(ip)
    except:
        messagebox.showerror("Invalid IP Range", "Please enter a valid IP range.")
        scan_btn.config(state=tk.NORMAL)
        return

    try:
        ports = list(range(*map(int, port_range.split("-"))))
    except:
        messagebox.showerror("Invalid Port Range", "Port range must be like 20-80")
        scan_btn.config(state=tk.NORMAL)
        return

    def threaded_scan():
        threads = []
        for ip in all_ips:
            t = threading.Thread(target=scan_host, args=(ip, ports, tree))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        scan_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Scan Complete", "IP scan finished!")

    threading.Thread(target=threaded_scan).start()

# ---------- CSV Export ---------- #
def export_to_csv(tree):
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
    if not file_path:
        return
    with open(file_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Hostname", "NetBIOS", "Open Ports"])
        for row in tree.get_children():
            writer.writerow(tree.item(row)["values"])
    messagebox.showinfo("Exported", "Results saved to CSV!")

# ---------- GUI Code ---------- #
def create_gui():
    root = tk.Tk()
    root.title("🛡️ Python Port & NetBIOS Scanner")
    root.geometry("800x550")
    root.resizable(False, False)

    input_frame = tk.Frame(root)
    input_frame.pack(pady=10)

    tk.Label(input_frame, text="Start IP:").grid(row=0, column=0, padx=5)
    start_ip_entry = tk.Entry(input_frame)
    start_ip_entry.insert(0, "192.168.1.1")
    start_ip_entry.grid(row=0, column=1, padx=5)

    tk.Label(input_frame, text="End IP:").grid(row=0, column=2, padx=5)
    end_ip_entry = tk.Entry(input_frame)
    end_ip_entry.insert(0, "192.168.1.10")
    end_ip_entry.grid(row=0, column=3, padx=5)

    tk.Label(input_frame, text="Port Range (e.g. 20-100):").grid(row=0, column=4, padx=5)
    port_entry = tk.Entry(input_frame)
    port_entry.insert(0, "20-100")
    port_entry.grid(row=0, column=5, padx=5)

    scan_btn = tk.Button(root, text="Start Scan 🔍", bg="#4CAF50", fg="white", width=20,
                         command=lambda: start_scan(start_ip_entry.get(), end_ip_entry.get(),
                                                    port_entry.get(), tree, scan_btn))
    scan_btn.pack(pady=10)

    tree_frame = tk.Frame(root)
    tree_frame.pack(pady=10, fill=tk.BOTH, expand=True)

    cols = ("IP Address", "Hostname", "NetBIOS", "Open Ports")
    tree = ttk.Treeview(tree_frame, columns=cols, show="headings")
    for col in cols:
        tree.heading(col, text=col)
        tree.column(col, anchor=tk.W, width=180)
    tree.pack(fill=tk.BOTH, expand=True)

    export_btn = tk.Button(root, text="📤 Export to CSV", bg="#2196F3", fg="white", command=lambda: export_to_csv(tree))
    export_btn.pack(pady=10)

    root.mainloop()

# ---------- Run App ---------- #
if __name__ == "__main__":
    create_gui()
