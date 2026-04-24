"""
Couches 1 & 2 — BackendSniffer
Capture réseau asynchrone (AsyncSniffer) + analyse protocolaire.

Couche 1 : capture brute via Scapy, buffer PCAP, filtres BPF
Couche 2 : décodage TLS/SNI, DNS inverse, analyse HTTP, ARP, ICMP

Note : la couche IDS (AlertEngine) a été retirée.
"""
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

import netifaces
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Raw
from scapy.layers import http
from scapy.layers.tls.all import TLS

from .stats import PacketStats


class BackendSniffer:
    """
    Couches 1 & 2 — Moteur de capture et d'analyse réseau.

    Architecture multi-thread :
        - Thread capture  : AsyncSniffer → packet_queue
        - Thread processeur : packet_queue → analyse → display_queue
        - Thread stats    : calcul PPS, proto_dist toutes les secondes
    """

    def __init__(self, interface: str | None = None):
        self.interface = interface or self._get_default_interface()
        self.running = False

        # Queues inter-threads
        self.packet_queue: deque = deque(maxlen=5000)  # limite mémoire
        self.display_queue = __import__('queue').Queue()

        # Couche 1 — Stats & buffer PCAP
        self.stats = PacketStats()
        self.pcap_buffer: deque = deque(maxlen=2000)

        # Couche 2 — Caches
        self.rdns_cache: dict = {}        # {ip: hostname}
        self.arp_table: dict = {}         # {ip: mac}

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #
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

    # ------------------------------------------------------------------ #
    #  Couche 1 — Capture                                                 #
    # ------------------------------------------------------------------ #
    def _get_default_interface(self) -> str:
        try:
            gws = netifaces.gateways()
            return gws.get('default', {}).get(netifaces.AF_INET, [None, 'eth0'])[1]
        except Exception:
            return 'eth0'

    def _run_sniffer(self, filter_exp: str | None) -> None:
        """Lance l'AsyncSniffer Scapy et le maintient jusqu'à l'arrêt."""
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
        """Exporte le buffer courant vers un fichier .pcap (Wireshark compatible)."""
        from scapy.all import wrpcap
        fn = filename or f"capture_{datetime.now().strftime('%Y%H%M%S')}.pcap"
        wrpcap(fn, list(self.pcap_buffer))
        return fn

    # ------------------------------------------------------------------ #
    #  Couche 2 — Enrichissement (DNS Inverse, TLS/SNI)                  #
    # ------------------------------------------------------------------ #
    def resolve_dns(self, ip: str) -> str:
        """Résolution DNS inverse avec cache (non-bloquant si déjà connu)."""
        if ip in self.rdns_cache:
            return self.rdns_cache[ip]
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.rdns_cache[ip] = name
            return name
        except Exception:
            return ip

    def _extract_tls_sni(self, packet) -> str | None:
        """Extrait le SNI du TLS ClientHello si disponible."""
        try:
            if packet.haslayer(TLS) and packet.haslayer(Raw):
                return "TLS Handshake"
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    #  Thread — Traitement des paquets                                    #
    # ------------------------------------------------------------------ #
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
        """Couche 2 — Analyse protocolaire multicouche."""
        self.stats.total_packets += 1
        protocol = "OTHER"
        info = ""
        source = "N/A"
        destination = "N/A"

        # — ARP —
        if ARP in packet:
            protocol = "ARP"
            self.stats.protocols['ARP'] += 1
            source = packet[ARP].hwsrc
            target_ip = packet[ARP].psrc
            self.arp_table[target_ip] = source
            info = f"{'Req' if packet[ARP].op == 1 else 'Rep'} {packet[ARP].psrc} → {packet[ARP].pdst}"

        # — IP —
        elif IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst
            self.stats.source_ips[source] += 1

            if TCP in packet:
                protocol = "TCP"
                self.stats.protocols['TCP'] += 1
                dport = packet[TCP].dport
                # TLS / SNI
                sni = self._extract_tls_sni(packet)
                if sni:
                    protocol = "TLS"
                    info = f"SNI: {sni}"
                # HTTP
                elif packet.haslayer(http.HTTPRequest):
                    protocol = "HTTP"
                    self.stats.protocols['HTTP'] += 1
                    try:
                        method = packet[http.HTTPRequest].Method.decode()
                        host = packet[http.HTTPRequest].Host.decode()
                        info = f"{method} {host}"
                    except Exception:
                        pass
                else:
                    info = f"{packet[TCP].sport} → {dport} [{packet[TCP].flags}]"

            elif UDP in packet:
                protocol = "UDP"
                self.stats.protocols['UDP'] += 1
                dport = packet[UDP].dport
                # DNS
                if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                    protocol = "DNS"
                    self.stats.protocols['DNS'] += 1
                    try:
                        qname = packet.getlayer(DNS).qd.qname.decode()
                        info = f"Query: {qname}"
                    except Exception:
                        pass
                else:
                    info = f"{packet[UDP].sport} → {dport}"

            elif ICMP in packet:
                protocol = "ICMP"
                self.stats.protocols['ICMP'] += 1
                info = f"Type: {packet[ICMP].type}"

        packet_data = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "length": len(packet),
            "info": info,
            "raw": packet,
            "summary": packet.summary(),
        }
        self.display_queue.put(packet_data)

    # ------------------------------------------------------------------ #
    #  Thread — Statistiques                                              #
    # ------------------------------------------------------------------ #
    def _track_stats(self) -> None:
        """Met à jour PPS, proto_dist et nettoie les maps de scan."""
        while self.running:
            time.sleep(1)
            self.stats.pps_history.append(self.stats.current_sec_packets)
            self.stats.current_sec_packets = 0
            total = sum(self.stats.protocols.values())
            if total > 0:
                self.stats.proto_dist = {
                    k: (v / total) * 100 for k, v in self.stats.protocols.items()
                }
