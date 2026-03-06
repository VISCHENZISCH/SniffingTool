import threading
import queue
import time
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, DNS
from scapy.layers import http
import netifaces

class PacketStats:
    """Statistics for captured packets."""
    def __init__(self):
        self.total_packets = 0
        self.protocols = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.dest_ips = defaultdict(int)
        self.ports = defaultdict(int)
        self.start_time = datetime.now()
        self.pps_history = deque([0] * 60, maxlen=60) # Last 60 seconds
        self.current_sec_packets = 0
        self.last_stats_update = time.time()

class BackendSniffer:
    """
    Back-end sniffer.
    """
    def __init__(self, interface=None):
        self.interface = interface or self._get_default_interface()
        self.packet_queue = queue.Queue()
        self.display_queue = queue.Queue()
        self.stats = PacketStats()
        self.running = False
        self.sniffer_thread = None
        self.processor_thread = None
        self.stats_thread = None
        self.dns_queries = defaultdict(int) # For DNS tunneling detection

    def _get_default_interface(self):
        """Get the default network interface."""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})
            return default_gateway.get(netifaces.AF_INET, [None, 'eth0'])[1]
        except Exception:
            return 'eth0'

    def start(self, filter_exp=None):
        """Start the sniffer threads."""
        self.running = True
        self.stats.start_time = datetime.now()
        
        # Start packet processing thread
        self.processor_thread = threading.Thread(target=self._process_packets, daemon=True)
        self.processor_thread.start()

        # Start stats tracking thread (for PPS)
        self.stats_thread = threading.Thread(target=self._track_pps, daemon=True)
        self.stats_thread.start()

        # Start scapy sniffer in a separate thread
        self.sniffer_thread = threading.Thread(target=self._run_sniffer, args=(filter_exp,), daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        """Stop the sniffer."""
        self.running = False

    def _run_sniffer(self, filter_exp):
        """Scapy sniffer loop."""
        def packet_handler(packet):
            if self.running:
                self.packet_queue.put(packet)
                self.stats.current_sec_packets += 1

        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                filter=filter_exp,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            # Error could be logged but for now we just fail gracefully
            pass

    def _track_pps(self):
        """Track packets per second."""
        while self.running:
            time.sleep(1)
            self.stats.pps_history.append(self.stats.current_sec_packets)
            self.stats.current_sec_packets = 0

    def _process_packets(self):
        """Process packets from the queue."""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=0.1)
                self._analyze_packet(packet)
            except queue.Empty:
                continue
            except Exception:
                pass

    def _analyze_packet(self, packet):
        """Analyze a single packet, update stats, and detect anomalies."""
        self.stats.total_packets += 1
        
        protocol = "OTHER"
        info = ""
        source = "N/A"
        destination = "N/A"
        alerts = []

        # Anomaly Detection Logic
        if self._detect_port_scan(packet):
            alerts.append("SCAN: SYN Only")
        if self._detect_dns_anomaly(packet):
            alerts.append("DNS: Potential Tunneling")
        if self._detect_http_credentials(packet):
            alerts.append("AUTH: Plaintext Found")

        if IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst
            self.stats.source_ips[source] += 1
            self.stats.dest_ips[destination] += 1
            
            if TCP in packet:
                protocol = "TCP"
                self.stats.protocols['TCP'] += 1
                self.stats.ports[packet[TCP].dport] += 1
                flags = packet[TCP].flags
                info = f"{packet[TCP].sport} → {packet[TCP].dport} [{flags}]"
                
                if packet.haslayer(http.HTTPRequest):
                    protocol = "HTTP"
                    self.stats.protocols['HTTP'] += 1
                    try:
                        method = packet[http.HTTPRequest].Method.decode()
                        host = packet[http.HTTPRequest].Host.decode()
                        info = f"{method} {host}"
                    except: pass
            elif UDP in packet:
                protocol = "UDP"
                self.stats.protocols['UDP'] += 1
                self.stats.ports[packet[UDP].dport] += 1
                info = f"{packet[UDP].sport} → {packet[UDP].dport}"
                
                if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                    protocol = "DNS"
                    self.stats.protocols['DNS'] += 1
                    qname = packet.getlayer(DNS).qd.qname.decode()
                    info = f"Query: {qname}"
            elif ICMP in packet:
                protocol = "ICMP"
                self.stats.protocols['ICMP'] += 1
                info = f"Type: {packet[ICMP].type}"
        
        elif ARP in packet:
            protocol = "ARP"
            self.stats.protocols['ARP'] += 1
            source = packet[ARP].hwsrc
            op = "Req" if packet[ARP].op == 1 else "Rep"
            info = f"{op} {packet[ARP].psrc} -> {packet[ARP].pdst}"

        packet_data = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "length": len(packet),
            "info": info,
            "alerts": alerts,
            "raw": packet,
            "summary": packet.summary()
        }
        
        self.display_queue.put(packet_data)

    def _detect_port_scan(self, packet) -> bool:
        if TCP in packet and packet[TCP].flags == "S":
            return True
        return False
    
    def _detect_dns_anomaly(self, packet) -> bool:
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            qname = packet.getlayer(DNS).qd.qname.decode()
            # Heuristic: long subdomain or excessive queries to same domain
            if len(qname) > 60: return True
            domain = ".".join(qname.split('.')[-3:])
            self.dns_queries[domain] += 1
            if self.dns_queries[domain] > 50: return True
        return False

    def _detect_http_credentials(self, packet) -> bool:
        if packet.haslayer(Raw):
            try:
                load = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                keywords = ['password=', 'pass=', 'pwd=', 'user=', 'username=', 'login=']
                return any(keyword in load for keyword in keywords)
            except: pass
        return False


