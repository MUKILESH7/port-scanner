import socket
import threading
import time
from services import COMMON_PORTS

open_ports = []

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown Service")
            print(f"[+] Port {port} OPEN ({service})")
            open_ports.append((port, service))
        s.close()
    except:
        pass

def main():
    target = input("Enter target IP or domain: ")
    start_port = int(input("Start Port: "))
    end_port = int(input("End Port: "))
    
    print(f"\n[*] Scanning {target} from port {start_port} to {end_port}...\n")
    time1 = time.time()
    
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

    time2 = time.time()
    print(f"\nScan Completed in {round(time2 - time1, 2)} seconds")
    if open_ports:
        print("\n🔓 Open Ports Summary:")
        for port, service in open_ports:
            print(f"Port {port} ({service})")
    else:
        print("🚫 No open ports found.")

if __name__ == "__main__":
    main()
