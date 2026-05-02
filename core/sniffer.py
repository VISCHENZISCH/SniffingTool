"""
Couches 1 & 2 — BackendSniffer
Capture réseau asynchrone (AsyncSniffer) + analyse protocolaire enrichie.
"""
import socket
import threading
import time
import re
from collections import defaultdict, deque
from datetime import datetime

import netifaces
from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, Raw, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers import http
from scapy.layers.tls.all import TLS

from .stats import PacketStats


class BackendSniffer:
    """
    Couches 1 & 2 — Moteur de capture et d'analyse réseau.
    Incorpore la détection d'OS (TTL/Window) et l'extraction de bannières.
    """

    def __init__(self, interface: str | None = None):
        self.interface = interface or self._get_default_interface()
        self.running = False

        # Queues inter-threads
        self.packet_queue: deque = deque(maxlen=5000)
        self.display_queue = __import__('queue').Queue()

        # Couche 1 — Stats & buffer PCAP
        self.stats = PacketStats()
        self.pcap_buffer: deque = deque(maxlen=2000)

        # Couche 2 — Caches
        self.rdns_cache: dict = {}        # {ip: nom d'hôte}
        self.arp_table: dict = {}         # {ip: mac}
        self.os_cache: dict = {}          # {ip: os_name}

    # Cycle de vie
    def start(self, filter_exp: str | None = None) -> None:
        """Démarre les threads de capture, traitement et statistiques."""
        self.running = True
        self.stats.start_time = datetime.now()
        threading.Thread(target=self._run_sniffer, args=(filter_exp,), daemon=True).start()
        threading.Thread(target=self._process_packets, daemon=True).start()
        threading.Thread(target=self._track_stats, daemon=True).start()

    def stop(self) -> None:
        """Arrête proprement tous les threads."""
        self.running = False

    # Couche 1 - Capture
    def _get_default_interface(self) -> str:
        try:
            gws = netifaces.gateways()
            return gws.get('default', {}).get(netifaces.AF_INET, [None, 'eth0'])[1]
        except Exception:
            return 'eth0'

    def _run_sniffer(self, filter_exp: str | None) -> None:
        """Lance l'AsyncSniffer Scapy."""
        from scapy.all import AsyncSniffer
        sniffer = AsyncSniffer(
            iface=self.interface,
            prn=lambda pkt: self.packet_queue.append(pkt) if self.running else None,
            filter=filter_exp,
            store=False,
        )
        sniffer.start()
        while self.running:
            time.sleep(0.5)
        sniffer.stop()

    def export_pcap(self, filename: str | None = None) -> str:
        """Exporte le buffer PCAP."""
        from scapy.all import wrpcap
        fn = filename or f"capture_{datetime.now().strftime('%Y%H%M%S')}.pcap"
        wrpcap(fn, list(self.pcap_buffer))
        return fn

    # Couche 2 - Enrichissement (DNS Inverse, TLS/SNI, OS Detection)
    def _detect_os(self, packet) -> str:
        """Analyse passive de l'OS via TTL et TCP Window Size."""
        if IP in packet:
            ttl = packet[IP].ttl
            window = packet[TCP].window if TCP in packet else 0
            
            # Heuristique simplifiée
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                if window == 8192 or window == 65535:
                    return "Windows 7/10/11"
                return "Windows"
            elif ttl <= 255:
                return "Network Device (Cisco/Solaris)"
        return "Inconnu"

    def _extract_banner(self, packet) -> str | None:
        """Tente d'extraire une bannière de service (SSH, FTP, HTTP Server)."""
        if Raw in packet:
            payload = str(packet[Raw].load)
            # SSH
            if "SSH-" in payload:
                match = re.search(r"SSH-[\d\.]+-[\w\._-]+", payload)
                if match: return match.group(0)
            # FTP / SMTP
            if payload.startswith("b'220"):
                return payload[2:50]
        return None

    def _extract_tls_sni(self, packet) -> str | None:
        """Extrait le SNI du TLS ClientHello."""
        try:
            if packet.haslayer(TLS):
                from scapy.layers.tls.extensions import TLS_Ext_ServerName
                if packet.haslayer(TLS_Ext_ServerName):
                    return packet[TLS_Ext_ServerName].servernames[0].servername.decode()
                return "TLS Handshake"
        except Exception:
            pass
        return None

    # Thread - Traitement des paquets
    def _process_packets(self) -> None:
        while self.running:
            if not self.packet_queue:
                time.sleep(0.005)
                continue
            packet = self.packet_queue.popleft()
            self.stats.current_sec_packets += 1
            self.pcap_buffer.append(packet)
            self._analyze_packet(packet)

    def _analyze_packet(self, packet) -> None:
        """Couche 2 — Analyse protocolaire enrichie."""
        self.stats.total_packets += 1
        protocol = "OTHER"
        info = ""
        source = "N/A"
        destination = "N/A"
        os_name = "N/A"
        ua = None

        if ARP in packet:
            protocol = "ARP"
            self.stats.protocols['ARP'] += 1
            source = packet[ARP].hwsrc
            target_ip = packet[ARP].psrc
            self.arp_table[target_ip] = source
            info = f"{'Req' if packet[ARP].op == 1 else 'Rep'} {packet[ARP].psrc} -> {packet[ARP].pdst}"

        elif IP in packet or IPv6 in packet:
            is_v6 = IPv6 in packet
            layer_ip = packet[IPv6] if is_v6 else packet[IP]
            source = layer_ip.src
            destination = layer_ip.dst
            self.stats.source_ips[source] += 1
            
            # OS Detection
            os_name = self._detect_os(packet)

            if TCP in packet:
                protocol = "TCP"
                self.stats.protocols['TCP'] += 1
                dport = packet[TCP].dport
                
                # Banner grabbing
                banner = self._extract_banner(packet)
                
                sni = self._extract_tls_sni(packet)
                if sni:
                    protocol = "TLS"
                    info = f"SNI: {sni}"
                elif packet.haslayer(http.HTTPRequest):
                    protocol = "HTTP"
                    self.stats.protocols['HTTP'] += 1
                    try:
                        req = packet[http.HTTPRequest]
                        method = req.Method.decode() if req.Method else "GET"
                        host = req.Host.decode() if req.Host else destination
                        path = req.Path.decode() if req.Path else "/"
                        info = f"{method} {host}{path}"
                        # User-Agent extraction
                        ua_val = getattr(req, 'User_Agent', None) or getattr(req, 'User-Agent', None)
                        if ua_val:
                            ua = ua_val.decode() if isinstance(ua_val, bytes) else str(ua_val)
                    except Exception: pass
                elif packet.haslayer(http.HTTPResponse):
                    protocol = "HTTP"
                    self.stats.protocols['HTTP'] += 1
                    try:
                        resp = packet[http.HTTPResponse]
                        code = resp.Status_Code.decode() if resp.Status_Code else "200"
                        phrase = resp.Reason_Phrase.decode() if resp.Reason_Phrase else "OK"
                        info = f"Response: {code} {phrase}"
                        # Server banner extraction from HTTP header
                        server = getattr(resp, 'Server', None)
                        if server:
                            info += f" | Server: {server.decode() if isinstance(server, bytes) else server}"
                    except Exception: pass
                elif banner:
                    info = f"Banner: {banner}"
                else:
                    info = f"{packet[TCP].sport} -> {dport} [{packet[TCP].flags}]"

            elif UDP in packet:
                protocol = "UDP"
                self.stats.protocols['UDP'] += 1
                dport = packet[UDP].dport
                if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                    protocol = "DNS"
                    self.stats.protocols['DNS'] += 1
                    try:
                        qname = packet.getlayer(DNS).qd.qname.decode()
                        info = f"Query: {qname}"
                    except Exception:
                        pass
                else:
                    info = f"{packet[UDP].sport} -> {dport}"

            elif ICMP in packet or (IPv6 in packet and (packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply))):
                protocol = "ICMP"
                self.stats.protocols['ICMP'] += 1
                if ICMP in packet:
                    info = f"Type: {packet[ICMP].type}"
                else:
                    info = "ICMPv6"

        # Identification de session (hash du 4-tuple)
        session_id = "N/A"
        ttl_val = 0
        tcp_flags = ""
        if IP in packet:
            ttl_val = packet[IP].ttl
            if TCP in packet:
                session_id = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
                tcp_flags = str(packet[TCP].flags)
            elif UDP in packet:
                session_id = f"{packet[IP].src}:{packet[UDP].sport}-{packet[IP].dst}:{packet[UDP].dport}"

        packet_data = {
            "id": self.stats.total_packets,
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "length": len(packet),
            "info": info,
            "os": os_name,
            "ua": ua,
            "flags": tcp_flags,
            "ttl": ttl_val,
            "session": hash(session_id) % 0xFFFF if session_id != "N/A" else "----",
            "raw": packet,
            "summary": packet.summary(),
        }
        self.display_queue.put(packet_data)

    # Thread - Statistiques
    def _track_stats(self) -> None:
        while self.running:
            time.sleep(1)
            self.stats.pps_history.append(self.stats.current_sec_packets)
            self.stats.current_sec_packets = 0
            total = sum(self.stats.protocols.values())
            if total > 0:
                self.stats.proto_dist = {
                    k: (v / total) * 100 for k, v in self.stats.protocols.items()
                }
