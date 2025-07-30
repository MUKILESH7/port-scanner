import socket
import subprocess
import ipaddress
import threading
import platform

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

def is_alive(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "500", str(ip)]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def scan_ports(ip, port_list):
    open_ports = []
    for port in port_list:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except:
        return "Unknown"

def scan_ip(ip):
    if is_alive(ip):
        hostname = resolve_hostname(ip)
        open_ports = scan_ports(ip, COMMON_PORTS.keys())
        print(f"\n🔍 {ip} ({hostname})")
        if open_ports:
            for port in open_ports:
                service = COMMON_PORTS.get(port, "Unknown")
                print(f"    🔓 Port {port} OPEN ({service})")
        else:
            print("    ⚠️ No common open ports found.")

def main():
    print("🔎 Custom IP Range Scanner")

    start_ip = input("Start IP (e.g., 192.168.1.1): ")
    end_ip = input("End IP   (e.g., 192.168.1.50): ")

    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        if start > end:
            print("⚠️ Start IP should be less than or equal to End IP.")
            return
    except:
        print("❌ Invalid IP format!")
        return

    threads = []
    for ip_int in range(int(start), int(end) + 1):
        ip = ipaddress.IPv4Address(ip_int)
        t = threading.Thread(target=scan_ip, args=(ip,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n✅ Scan complete!")

if __name__ == "__main__":
    main()
