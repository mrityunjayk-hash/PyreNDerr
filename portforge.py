#!/usr/bin/env python3

import socket
import struct
import sys
import os
import time
import random
import ipaddress
import threading
import argparse
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
import select

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

BANNER = r"""
  ____  _  _ ____  ____   _  _  __   __ _  ____  ____  __   ____  ____ 
 (  _ \( \/ )  _ \(  __) ( \/ )/ _\ (  ( \(  _ \(  __)(  ) (  _ \(  _ \
  ) __/ )  ( )   / ) _)   )  //    \/    / )   / ) _)  )(   )   / ) __/
 (__)  (_/\_)(__\_)(____) (__/ \_/\_/\_)__)(__\_)(____)(__)  (__\_)(__)  
                               v1.0 - Advanced Port Scanner
"""

SERVICE_DB = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    179: "bgp", 194: "irc", 389: "ldap", 443: "https", 445: "smb",
    464: "kpasswd", 465: "smtps", 500: "isakmp", 512: "exec",
    513: "login", 514: "syslog", 515: "printer", 543: "klogin",
    544: "kshell", 587: "submission", 593: "http-rpc-epmap",
    631: "ipp", 636: "ldaps", 873: "rsync", 902: "iss-realsecure",
    989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
    2376: "docker-ssl", 3000: "dev-server", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4444: "metasploit", 5000: "flask",
    5432: "postgresql", 5900: "vnc", 5985: "winrm-http",
    5986: "winrm-https", 6379: "redis", 6443: "k8s-api",
    7001: "weblogic", 7547: "cwmp", 8080: "http-proxy",
    8443: "https-alt", 8888: "jupyter", 9200: "elasticsearch",
    9300: "elasticsearch-cluster", 10250: "kubelet",
    27017: "mongodb", 50000: "db2",
}

PROBE_PAYLOADS = {
    "http": b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    "ssh": b"SSH-2.0-OpenSSH_8.0\r\n",
    "ftp": b"USER anonymous\r\n",
    "smtp": b"EHLO scanner.local\r\n",
    "mysql": b"\x0a",
    "redis": b"*1\r\n$4\r\nPING\r\n",
    "mongo": b"\x41\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x10serverStatus\x00\x01\x00\x00\x00\x00",
    "generic": b"\x00",
}

OS_FINGERPRINTS = {
    "ttl_128": "Windows",
    "ttl_64": "Linux/Unix",
    "ttl_255": "Cisco/Network Device",
    "ttl_60": "macOS/BSD",
}

VULN_DB = {
    21: [{"id": "CVE-2011-2523", "desc": "vsftpd 2.3.4 Backdoor Command Execution", "check": lambda b: b"vsFTPd 2.3.4" in b}],
    22: [
        {"id": "CVE-2008-0166", "desc": "OpenSSL Debian weak keys", "check": lambda b: b"OpenSSH" in b},
        {"id": "CVE-2016-0777", "desc": "OpenSSH UseRoaming information leak", "check": lambda b: b"OpenSSH" in b},
    ],
    80: [{"id": "CVE-2017-5638", "desc": "Apache Struts RCE (check manually)", "check": lambda b: b"Apache" in b}],
    443: [{"id": "CVE-2014-0160", "desc": "Heartbleed - check TLS version", "check": lambda b: len(b) > 0}],
    3306: [{"id": "CVE-2012-2122", "desc": "MySQL auth bypass with repeated attempts", "check": lambda b: b"mysql" in b.lower()}],
    6379: [{"id": "CVE-2015-8080", "desc": "Redis unauthenticated access", "check": lambda b: b"+PONG" in b}],
}

@dataclass
class PortResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""
    version: str = ""
    proto: str = "tcp"
    reason: str = ""
    vulns: list = field(default_factory=list)

@dataclass
class HostResult:
    host: str
    ip: str = ""
    state: str = "down"
    os_guess: str = ""
    ttl: int = 0
    latency: float = 0.0
    open_ports: list = field(default_factory=list)
    filtered_ports: list = field(default_factory=list)
    closed_ports: list = field(default_factory=list)
    mac: str = ""
    hostname: str = ""
    scan_time: float = 0.0


class RawScanner:
    def __init__(self):
        self.icmp_sock = None
        self.tcp_sock = None

    def ping_icmp(self, target_ip, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            icmp_type = 8
            icmp_code = 0
            icmp_id = random.randint(1, 65535)
            icmp_seq = 1
            data = b"PYRENDERR" * 4
            header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, icmp_seq)
            checksum = self._checksum(header + data)
            header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            packet = header + data
            start = time.time()
            sock.sendto(packet, (target_ip, 0))
            while True:
                ready = select.select([sock], [], [], timeout)
                if not ready[0]:
                    sock.close()
                    return False, 0, 0
                recv_packet, addr = sock.recvfrom(1024)
                latency = (time.time() - start) * 1000
                ip_header = recv_packet[:20]
                ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
                ttl = ip_fields[5]
                icmp_header = recv_packet[20:28]
                icmp_fields = struct.unpack("!BBHHH", icmp_header)
                if icmp_fields[0] == 0 and icmp_fields[3] == icmp_id:
                    sock.close()
                    return True, ttl, latency
        except PermissionError:
            return self._ping_connect(target_ip, timeout)
        except Exception:
            return False, 0, 0

    def _ping_connect(self, target_ip, timeout=2):
        for port in [80, 443, 22, 21, 8080]:
            try:
                start = time.time()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((target_ip, port))
                latency = (time.time() - start) * 1000
                s.close()
                if result in [0, 111]:
                    return True, 0, latency
            except Exception:
                continue
        return False, 0, 0

    def syn_scan_port(self, target_ip, port, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)
            src_ip = self._get_src_ip(target_ip)
            src_port = random.randint(1024, 65535)
            seq_num = random.randint(0, 4294967295)
            ip_header = self._build_ip_header(src_ip, target_ip)
            tcp_header = self._build_tcp_header(src_ip, target_ip, src_port, port, seq_num, 0, "S")
            packet = ip_header + tcp_header
            sock.sendto(packet, (target_ip, 0))
            start = time.time()
            while time.time() - start < timeout:
                ready = select.select([sock], [], [], timeout)
                if not ready[0]:
                    break
                data, addr = sock.recvfrom(65535)
                if addr[0] != target_ip:
                    continue
                ip_hdr_len = (data[0] & 0xF) * 4
                tcp_data = data[ip_hdr_len:]
                if len(tcp_data) < 20:
                    continue
                tcp_fields = struct.unpack("!HHLLBBHHH", tcp_data[:20])
                dport = tcp_fields[0]
                sport = tcp_fields[1]
                flags = tcp_fields[5]
                if sport == port:
                    rst_ack = flags & 0x14
                    syn_ack = flags & 0x12
                    rst = flags & 0x04
                    if syn_ack == 0x12:
                        rst_header = self._build_tcp_header(src_ip, target_ip, src_port, port, seq_num + 1, tcp_fields[3] + 1, "R")
                        sock.sendto(ip_header + rst_header, (target_ip, 0))
                        sock.close()
                        return "open"
                    elif rst:
                        sock.close()
                        return "closed"
            sock.close()
            return "filtered"
        except PermissionError:
            return None
        except Exception:
            return None

    def _get_src_ip(self, target_ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target_ip, 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _checksum(self, data):
        s = 0
        n = len(data) % 2
        for i in range(0, len(data) - n, 2):
            s += (data[i]) + ((data[i+1]) << 8)
        if n:
            s += data[-1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xFFFF
        return s

    def _build_ip_header(self, src_ip, dst_ip):
        version = 4
        ihl = 5
        tos = 0
        total_length = 40
        identification = random.randint(0, 65535)
        fragment_offset = 0
        ttl = 64
        protocol = socket.IPPROTO_TCP
        checksum = 0
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        header = struct.pack("!BBHHHBBH4s4s",
            (version << 4) + ihl, tos, total_length, identification,
            fragment_offset, ttl, protocol, checksum, src, dst)
        checksum = self._checksum(header)
        header = struct.pack("!BBHHHBBH4s4s",
            (version << 4) + ihl, tos, total_length, identification,
            fragment_offset, ttl, protocol, socket.htons(checksum), src, dst)
        return header

    def _build_tcp_header(self, src_ip, dst_ip, src_port, dst_port, seq, ack_seq, flags_str):
        data_offset = 5
        fin = syn = rst = psh = ack = urg = 0
        for c in flags_str:
            if c == "F": fin = 1
            elif c == "S": syn = 1
            elif c == "R": rst = 1
            elif c == "P": psh = 1
            elif c == "A": ack = 1
            elif c == "U": urg = 1
        flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        window = socket.htons(5840)
        checksum = 0
        urgent_ptr = 0
        offset_res = (data_offset << 4) + 0
        header = struct.pack("!HHLLBBHHH",
            src_port, dst_port, seq, ack_seq, offset_res, flags, window, checksum, urgent_ptr)
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        pseudo = struct.pack("!4s4sBBH", src, dst, 0, socket.IPPROTO_TCP, len(header))
        checksum = self._checksum(pseudo + header)
        header = struct.pack("!HHLLBBHHH",
            src_port, dst_port, seq, ack_seq, offset_res, flags, window, socket.htons(checksum), urgent_ptr)
        return header


class PortScanner:
    def __init__(self, args):
        self.args = args
        self.raw = RawScanner()
        self.results = {}
        self.lock = threading.Lock()
        self._print_lock = threading.Lock()

    def resolve_host(self, host):
        try:
            ip = socket.gethostbyname(host)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""
            return ip, hostname
        except socket.gaierror as e:
            return None, None

    def parse_ports(self, port_str):
        if port_str == "-":
            return list(range(1, 65536))
        if port_str == "top100":
            return list(SERVICE_DB.keys())[:100]
        if port_str == "top1000":
            top = list(SERVICE_DB.keys())
            common = list(range(1, 1024))
            result = list(set(top + common))
            return sorted(result)[:1000]
        ports = set()
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def parse_targets(self, target_str):
        targets = []
        for t in target_str.split(","):
            t = t.strip()
            if "/" in t:
                try:
                    net = ipaddress.ip_network(t, strict=False)
                    targets.extend([str(ip) for ip in net.hosts()])
                except ValueError:
                    targets.append(t)
            elif "-" in t.split(".")[-1]:
                base = ".".join(t.split(".")[:-1])
                last = t.split(".")[-1]
                start, end = last.split("-")
                for i in range(int(start), int(end) + 1):
                    targets.append(f"{base}.{i}")
            else:
                targets.append(t)
        return targets

    def tcp_connect_scan(self, ip, port, timeout):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                return "open"
            elif result in [111, 10061]:
                return "closed"
            else:
                return "filtered"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except Exception:
            return "filtered"

    def udp_scan(self, ip, port, timeout):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            payload = PROBE_PAYLOADS.get("generic", b"\x00")
            s.sendto(payload, (ip, port))
            try:
                data, addr = s.recvfrom(1024)
                s.close()
                return "open"
            except socket.timeout:
                s.close()
                return "open|filtered"
        except Exception:
            return "filtered"

    def grab_banner(self, ip, port, timeout=3):
        banner = b""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.settimeout(2)
                banner = s.recv(1024)
            except Exception:
                pass
            if not banner:
                service = SERVICE_DB.get(port, "")
                probe = None
                if port in [80, 8080, 8443, 443]:
                    probe = PROBE_PAYLOADS["http"]
                elif service == "ftp":
                    probe = PROBE_PAYLOADS["ftp"]
                elif service == "smtp":
                    probe = PROBE_PAYLOADS["smtp"]
                elif service == "redis":
                    probe = PROBE_PAYLOADS["redis"]
                if probe:
                    s.send(probe)
                    try:
                        banner = s.recv(1024)
                    except Exception:
                        pass
            s.close()
        except Exception:
            pass
        return banner

    def detect_version(self, port, banner):
        if not banner:
            return ""
        patterns = [
            (r"SSH-(\d+\.\d+)-(\S+)", "SSH"),
            (r"OpenSSH[_/](\S+)", "OpenSSH"),
            (r"Apache[/\s](\d+\.\d+\.\d+)", "Apache httpd"),
            (r"nginx[/\s](\d+\.\d+\.\d+)", "nginx"),
            (r"Microsoft-IIS[/\s](\S+)", "Microsoft IIS"),
            (r"vsftpd (\S+)", "vsftpd"),
            (r"ProFTPD (\S+)", "ProFTPD"),
            (r"Postfix", "Postfix smtpd"),
            (r"Exim (\S+)", "Exim smtpd"),
            (r"MySQL.*?(\d+\.\d+\.\d+)", "MySQL"),
            (r"MariaDB.*?(\d+\.\d+\.\d+)", "MariaDB"),
            (r"\+PONG", "Redis"),
            (r"HTTP/(\d+\.\d+)", "HTTP"),
        ]
        banner_str = banner.decode("utf-8", errors="replace")
        for pattern, name in patterns:
            m = re.search(pattern, banner_str, re.IGNORECASE)
            if m:
                if m.lastindex and m.lastindex >= 1:
                    return f"{name} {m.group(1)}"
                return name
        return ""

    def check_vulns(self, port, banner):
        if port not in VULN_DB:
            return []
        findings = []
        for vuln in VULN_DB[port]:
            try:
                if vuln["check"](banner):
                    findings.append(vuln)
            except Exception:
                pass
        return findings

    def guess_os(self, ttl):
        if ttl == 0:
            return ""
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco/Network Device"
        return "Unknown"

    def scan_port(self, ip, port, scan_type, timeout):
        if scan_type == "syn":
            state = self.raw.syn_scan_port(ip, port, timeout)
            if state is None:
                state = self.tcp_connect_scan(ip, port, timeout)
        elif scan_type == "udp":
            state = self.udp_scan(ip, port, timeout)
        elif scan_type == "null":
            state = self._flag_scan(ip, port, timeout, "")
        elif scan_type == "fin":
            state = self._flag_scan(ip, port, timeout, "F")
        elif scan_type == "xmas":
            state = self._flag_scan(ip, port, timeout, "FPU")
        elif scan_type == "ack":
            state = self._ack_scan(ip, port, timeout)
        else:
            state = self.tcp_connect_scan(ip, port, timeout)

        result = PortResult(
            port=port,
            state=state,
            service=SERVICE_DB.get(port, "unknown"),
            proto="udp" if scan_type == "udp" else "tcp",
        )

        if state == "open" and not self.args.no_service:
            banner = self.grab_banner(ip, port, timeout)
            result.banner = banner.decode("utf-8", errors="replace").strip()[:200]
            result.version = self.detect_version(port, banner)
            if self.args.script:
                result.vulns = self.check_vulns(port, banner)

        return result

    def _flag_scan(self, ip, port, timeout, flags):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)
            src_ip = self.raw._get_src_ip(ip)
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 4294967295)
            ip_hdr = self.raw._build_ip_header(src_ip, ip)
            tcp_hdr = self.raw._build_tcp_header(src_ip, ip, src_port, port, seq, 0, flags)
            sock.sendto(ip_hdr + tcp_hdr, (ip, 0))
            ready = select.select([sock], [], [], timeout)
            if not ready[0]:
                sock.close()
                return "open|filtered"
            data, addr = sock.recvfrom(65535)
            ip_hdr_len = (data[0] & 0xF) * 4
            tcp_data = data[ip_hdr_len:]
            tcp_fields = struct.unpack("!HHLLBBHHH", tcp_data[:20])
            rst = tcp_fields[5] & 0x04
            sock.close()
            if rst:
                return "closed"
            return "open"
        except PermissionError:
            return self.tcp_connect_scan(ip, port, timeout)
        except Exception:
            return "filtered"

    def _ack_scan(self, ip, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)
            src_ip = self.raw._get_src_ip(ip)
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 4294967295)
            ip_hdr = self.raw._build_ip_header(src_ip, ip)
            tcp_hdr = self.raw._build_tcp_header(src_ip, ip, src_port, port, seq, 0, "A")
            sock.sendto(ip_hdr + tcp_hdr, (ip, 0))
            ready = select.select([sock], [], [], timeout)
            if not ready[0]:
                sock.close()
                return "filtered"
            data, addr = sock.recvfrom(65535)
            ip_hdr_len = (data[0] & 0xF) * 4
            tcp_data = data[ip_hdr_len:]
            tcp_fields = struct.unpack("!HHLLBBHHH", tcp_data[:20])
            rst = tcp_fields[5] & 0x04
            sock.close()
            return "unfiltered" if rst else "filtered"
        except PermissionError:
            return "unknown"
        except Exception:
            return "filtered"

    def scan_host(self, host, ports, scan_type, timeout, skip_ping=False):
        start = time.time()
        ip, hostname = self.resolve_host(host)
        if ip is None:
            self._print(f"[-] Could not resolve: {host}")
            return None

        result = HostResult(host=host, ip=ip, hostname=hostname or "")

        if not skip_ping:
            alive, ttl, latency = self.raw.ping_icmp(ip)
            if not alive:
                result.state = "down"
                return result
            result.ttl = ttl
            result.latency = round(latency, 2)
            result.os_guess = self.guess_os(ttl)
        else:
            result.state = "up"

        result.state = "up"

        workers = min(self.args.threads, len(ports))
        port_results = []

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self.scan_port, ip, p, scan_type, timeout): p for p in ports}
            for future in as_completed(futures):
                pr = future.result()
                if pr:
                    port_results.append(pr)
                    if pr.state == "open":
                        with self._print_lock:
                            self._print_port(ip, pr)

        for pr in port_results:
            if pr.state == "open":
                result.open_ports.append(pr)
            elif pr.state == "filtered" or pr.state == "open|filtered":
                result.filtered_ports.append(pr)
            else:
                result.closed_ports.append(pr)

        result.scan_time = round(time.time() - start, 2)
        return result

    def _print(self, msg):
        with self._print_lock:
            print(msg)

    def _print_port(self, ip, pr):
        state_color = "\033[92m" if pr.state == "open" else "\033[93m"
        reset = "\033[0m"
        version_info = f"  {pr.version}" if pr.version else ""
        print(f"  {state_color}{pr.port}/{pr.proto:<5}{reset}  {pr.state:<12}  {pr.service:<20}{version_info}")
        if pr.vulns:
            for v in pr.vulns:
                print(f"    \033[91m[VULN] {v['id']}: {v['desc']}\033[0m")

    def print_host_header(self, result):
        print(f"\n{'='*60}")
        print(f"\033[1mScan report for {result.host}")
        if result.ip != result.host:
            print(f"  ({result.ip})\033[0m")
        else:
            print("\033[0m", end="")
        if result.hostname:
            print(f"  Hostname: {result.hostname}")
        if result.state == "up":
            status = "\033[92mup\033[0m"
            latency_str = f" ({result.latency}ms latency)" if result.latency else ""
            print(f"  Host is {status}{latency_str}")
            if result.os_guess:
                print(f"  OS guess: {result.os_guess} (TTL={result.ttl})")
        else:
            print(f"  Host is \033[91mdown\033[0m")
        print(f"{'='*60}")
        if result.state == "up":
            print(f"  {'PORT':<10}  {'STATE':<12}  {'SERVICE':<20}  VERSION")
            print(f"  {'-'*60}")

    def print_summary(self, results, total_time):
        total_hosts = len(results)
        up_hosts = sum(1 for r in results if r and r.state == "up")
        total_open = sum(len(r.open_ports) for r in results if r)
        print(f"\n{'='*60}")
        print(f"\033[1mScan Summary\033[0m")
        print(f"  Hosts scanned  : {total_hosts}")
        print(f"  Hosts up       : {up_hosts}")
        print(f"  Hosts down     : {total_hosts - up_hosts}")
        print(f"  Open ports     : {total_open}")
        print(f"  Scan duration  : {total_time:.2f}s")
        print(f"  Scan completed : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")

    def save_output(self, results, filename, fmt):
        if fmt == "json":
            data = []
            for r in results:
                if not r:
                    continue
                data.append({
                    "host": r.host,
                    "ip": r.ip,
                    "state": r.state,
                    "os_guess": r.os_guess,
                    "latency": r.latency,
                    "open_ports": [
                        {
                            "port": p.port,
                            "proto": p.proto,
                            "service": p.service,
                            "version": p.version,
                            "banner": p.banner,
                            "vulns": [{"id": v["id"], "desc": v["desc"]} for v in p.vulns],
                        }
                        for p in r.open_ports
                    ]
                })
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
        elif fmt == "xml":
            lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<scanresults>']
            for r in results:
                if not r:
                    continue
                lines.append(f'  <host ip="{r.ip}" state="{r.state}" os="{r.os_guess}" latency="{r.latency}">')
                for p in r.open_ports:
                    lines.append(f'    <port number="{p.port}" proto="{p.proto}" service="{p.service}" version="{p.version}"/>')
                lines.append('  </host>')
            lines.append('</scanresults>')
            with open(filename, "w") as f:
                f.write("\n".join(lines))
        elif fmt == "grep":
            with open(filename, "w") as f:
                for r in results:
                    if not r or r.state != "up":
                        continue
                    for p in r.open_ports:
                        f.write(f"{r.ip}\t{p.port}\t{p.proto}\t{p.service}\t{p.version}\n")
        print(f"\n[+] Output saved to {filename}")

    def run(self):
        print("\033[96m" + BANNER + "\033[0m")

        targets = self.parse_targets(self.args.target)
        ports = self.parse_ports(self.args.ports)
        scan_type = self.args.scan_type
        timeout = self.args.timeout

        print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Targets     : {len(targets)} host(s)")
        print(f"[*] Ports       : {len(ports)} port(s)")
        print(f"[*] Scan type   : {scan_type.upper()}")
        print(f"[*] Threads     : {self.args.threads}")
        print(f"[*] Timeout     : {timeout}s")

        if self.args.randomize:
            random.shuffle(ports)

        if self.args.delay:
            print(f"[*] Delay       : {self.args.delay}s between ports")

        total_start = time.time()
        all_results = []

        for target in targets:
            result = self.scan_host(target, ports, scan_type, timeout, skip_ping=self.args.skip_ping)
            if result:
                self.print_host_header(result)
                if result.state == "up":
                    for pr in sorted(result.open_ports, key=lambda x: x.port):
                        pass
                    if not result.open_ports:
                        print(f"  All {len(ports)} scanned ports are closed/filtered")
                all_results.append(result)

        total_time = time.time() - total_start
        self.print_summary(all_results, total_time)

        if self.args.output:
            fmt = self.args.output_format or "json"
            self.save_output(all_results, self.args.output, fmt)


def main():
    parser = argparse.ArgumentParser(
        description="PyreNDerr - Advanced Python Port Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target host(s): IP, hostname, CIDR, or range (e.g. 192.168.1.1-254)")
    parser.add_argument("-p", "--ports", default="top1000",
        help="Ports: 22,80,443 | 1-1024 | - (all) | top100 | top1000 (default)")
    parser.add_argument("-sS", "--syn", dest="scan_type", action="store_const", const="syn",
        help="SYN scan (requires root)")
    parser.add_argument("-sT", "--connect", dest="scan_type", action="store_const", const="connect",
        help="TCP connect scan (default)")
    parser.add_argument("-sU", "--udp", dest="scan_type", action="store_const", const="udp",
        help="UDP scan")
    parser.add_argument("-sN", "--null", dest="scan_type", action="store_const", const="null",
        help="NULL scan")
    parser.add_argument("-sF", "--fin", dest="scan_type", action="store_const", const="fin",
        help="FIN scan")
    parser.add_argument("-sX", "--xmas", dest="scan_type", action="store_const", const="xmas",
        help="XMAS scan")
    parser.add_argument("-sA", "--ack", dest="scan_type", action="store_const", const="ack",
        help="ACK scan (firewall mapping)")
    parser.add_argument("--script", action="store_true",
        help="Enable basic vulnerability checks (NSE-like)")
    parser.add_argument("-Pn", "--skip-ping", dest="skip_ping", action="store_true",
        help="Skip host discovery, treat all hosts as up")
    parser.add_argument("-n", "--no-service", dest="no_service", action="store_true",
        help="Disable banner/service grabbing")
    parser.add_argument("--threads", type=int, default=100,
        help="Number of parallel threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.5,
        help="Per-port timeout in seconds (default: 1.5)")
    parser.add_argument("--delay", type=float, default=0,
        help="Delay between port probes (IDS evasion)")
    parser.add_argument("--randomize", action="store_true",
        help="Randomize port scan order")
    parser.add_argument("-o", "--output", metavar="FILE",
        help="Save output to file")
    parser.add_argument("--output-format", choices=["json", "xml", "grep"],
        help="Output format: json, xml, grep (default: json)")
    parser.add_argument("-T", "--timing", type=int, choices=[0,1,2,3,4,5], default=3,
        help="Timing template 0-5 (0=paranoid, 5=insane)")

    parser.set_defaults(scan_type="connect")
    args = parser.parse_args()

    timing_presets = {
        0: (0.5, 5.0, 5),
        1: (0.3, 3.0, 10),
        2: (0.1, 2.0, 30),
        3: (0.0, 1.5, 100),
        4: (0.0, 1.0, 200),
        5: (0.0, 0.5, 500),
    }
    delay, timeout, threads = timing_presets[args.timing]
    if not args.delay:
        args.delay = delay
    if args.timeout == 1.5:
        args.timeout = timeout
    if args.threads == 100:
        args.threads = threads

    scanner = PortScanner(args)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
