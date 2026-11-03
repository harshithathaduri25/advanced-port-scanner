import socket
import concurrent.futures
import ftplib
import smtplib
import requests
import paramiko
import dns.resolver

def get_service_version(target, port):
    # HTTP Banner Grab
    if port == 80:
        try:
            response = requests.get(f"http://{target}:{port}", timeout=2)
            server_header = response.headers.get("Server")
            if server_header:
                return server_header
        except requests.exceptions.RequestException:
            return None

    # FTP Banner Grab
    elif port == 21:
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=2)
            server_banner = ftp.getwelcome()
            ftp.quit()
            if server_banner:
                return server_banner
        except ftplib.all_errors:
            return None

    # SSH Banner Grab
    elif port == 22:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, port, timeout=2)
            server_version = ssh.get_transport().remote_version
            ssh.close()
            if server_version:
                return server_version
        except Exception:
            return None

    # Modern Socket-Based Telnet Banner Grab (Replacing removed telnetlib)
    elif port == 23:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))
            # Send a basic newline to provoke a login banner or read initial response
            banner = s.recv(1024).decode(errors='ignore').strip()
            s.close()
            if banner:
                # Filter out raw telnet negotiation control bytes if they appear
                clean_banner = "".join(i for i in banner if 32 <= ord(i) < 127 or i in "\n\r")
                return clean_banner if clean_banner.strip() else "Telnet Service Active"
        except Exception:
            return None

    # SMTP Banner Grab
    elif port == 25:
        try:
            smtp = smtplib.SMTP(target, port, timeout=2)
            server_banner = smtp.helo()[0]
            smtp.quit()
            if server_banner:
                return str(server_banner)
        except smtplib.SMTPException:
            return None

    # DNS Version Grab
    elif port == 53:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [target]
            answer = resolver.resolve("_version.bind.", "TXT", lifetime=2)
            for rdata in answer:
                for txt_string in rdata.strings:
                    version_info = txt_string.decode()
                    if version_info:
                        return version_info
        except Exception:
            return None
            
    return None

def scan_single_port(target, port, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target, port))
    sock.close()
    return port, result

def run_port_scan(target, start_port=1, end_port=1024):
    scan_results = {"target": target, "open_ports": []}
    timeout = 2
    ports_to_scan = list(range(start_port, end_port + 1))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_single_port, target, p, timeout) for p in ports_to_scan]
        
        for future in concurrent.futures.as_completed(futures):
            port, result = future.result()
            if result == 0:
                try:
                    service_name = socket.getservbyport(port)
                except Exception:
                    service_name = "unknown"
                    
                version = get_service_version(target, port)
                scan_results["open_ports"].append({
                    "port": port,
                    "service": service_name,
                    "version": version if version else "Unknown Version"
                })
                
    return scan_results