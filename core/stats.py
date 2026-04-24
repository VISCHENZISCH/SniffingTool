"""
Couche 1 — PacketStats
Stocke toutes les métriques de capture en temps réel.
"""
import time
from collections import defaultdict, deque
from datetime import datetime


class PacketStats:
    """Statistiques globales de la session de capture."""
    def __init__(self):
        self.total_packets: int = 0
        self.protocols = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.ports = defaultdict(int)
        self.start_time = datetime.now()
        # PPS : historique glissant des 60 dernières secondes
        self.pps_history: deque = deque([0] * 60, maxlen=60)
        self.current_sec_packets: int = 0
        self.last_stats_update: float = time.time()
        # Répartition en % pour les graphiques (mis à jour par le thread stats)
        self.proto_dist: dict = {}
