"""
Couche 4 — Widgets Textual
Composants visuels réutilisables pour le dashboard TUI.
"""
import time
from textual.containers import Horizontal, Vertical
from textual.widgets import Static, Label
from textual.app import ComposeResult
from rich.text import Text
from rich.panel import Panel

class StatsCard(Static):
    def __init__(self, label: str, value_id: str, initial_value: str = "0", **kwargs):
        super().__init__(id=value_id, **kwargs)
        self.label = label
        self.value_id = value_id
        self.value = initial_value

    def update_value(self, new_value: str) -> None:
        self.value = new_value
        self.refresh()

    def render(self) -> Text:
        # Adaptatif au thème
        is_dark = getattr(self.app, "dark_mode", True)
        border_color = "#333333" if is_dark else "#D1D5DB"
        text_color = "#FF6600" if is_dark else "#EA580C"
        label_color = "#6B7280" if is_dark else "#4B5563"
        
        return Text.from_markup(
            f"[{label_color}]┌ {self.label} ┐[/]\n"
            f"[{text_color}]  {self.value.center(len(self.label))}  [/]\n"
            f"[{border_color}]└{'─' * (len(self.label) + 2)}┘[/]"
        )

class PPSGraph(Static):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.history = []

    def update_history(self, history: list) -> None:
        self.history = list(history)
        self.refresh()

    def render(self) -> Text:
        is_dark = getattr(self.app, "dark_mode", True)
        if not self.history:
            return Text("Graphique PPS...", style="#525252" if is_dark else "#9CA3AF")
        
        chars = " ▂▃▄▅▆▇█"
        width = 40
        data = self.history[-width:]
        if not data: return Text("")
        
        max_v = max(data) if max(data) > 0 else 1
        res = Text()
        color = "#FF6600" if is_dark else "#EA580C"
        for v in data:
            idx = int((v / max_v) * 7)
            res.append(chars[idx], style=color)
        return res

class GeoMap(Static):
    MAP = [
        r"            __________            ",
        r"         .-'          '-.         ",
        r"        /  [NA]    [EU]  \        ",
        r"    _  |  _          _  |  _      ",
        r"   ( \ |,.--..____..--.,| / )     ",
        r"    > '=.  [SA]  [AS]   .=' <     ",
        r"   (_/'=.  _ |/ [AF] \|  .='\_)   ",
        r"        '=.  (  [OC]  )  .='      ",
        r"            '=\__|IIIIII|__/='    ",
        r"            _.='| \IIIIII/ |'=.   ",
        r"    _  .='  .=' \ /'=.  '=.  _    ",
        r"   ( \_.='  _  '--------'  _  .='_/ )",
        r"    >  .='  '=.  <                ",
        r"   (_/  jgs  \_)                 ",
    ]
    
    ZONE_MAPPING = {
        "US": "NA", "CA": "NA", "MX": "NA",
        "FR": "EU", "DE": "EU", "GB": "EU", "IT": "EU", "ES": "EU", "RU": "EU",
        "CN": "AS", "JP": "AS", "IN": "AS", "KR": "AS",
        "BR": "SA", "AR": "SA", "CL": "SA",
        "ZA": "AF", "EG": "AF", "NG": "AF",
        "AU": "OC", "NZ": "OC"
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.active_zones = {}
        self.active_connections = [] # List of (src, dst, expiry)

    def pulse_zone(self, country_code: str) -> None:
        zone = self.ZONE_MAPPING.get(country_code, "??")
        if zone != "??":
            self.active_zones[zone] = time.time() + 1.0
            self.refresh()

    def pulse_connection(self, src_country: str, dst_country: str) -> None:
        src = self.ZONE_MAPPING.get(src_country)
        dst = self.ZONE_MAPPING.get(dst_country)
        if src and dst and src != dst:
            self.active_connections.append((src, dst, time.time() + 1.2))
            if len(self.active_connections) > 3: self.active_connections.pop(0)
            self.refresh()

    def render(self) -> Text:
        is_dark = getattr(self.app, "dark_mode", True)
        now = time.time()
        res = Text()
        pulse_color = "#FF6600" if is_dark else "#EA580C"
        base_color = "#445588" if is_dark else "#6B7280"
        
        # Filtrer les connexions expirées
        self.active_connections = [c for c in self.active_connections if c[2] > now]

        for line in self.MAP:
            formatted_line = line
            for zone in ["NA", "EU", "AS", "SA", "AF", "OC"]:
                active = self.active_zones.get(zone, 0) > now
                # Si zone impliquée dans une connexion active
                conn_active = any(zone in [c[0], c[1]] for c in self.active_connections)
                
                if active or conn_active:
                    color = f"bold {pulse_color} on #331A00"
                else:
                    color = base_color
                formatted_line = formatted_line.replace(f"[{zone}]", f"[[{color}]{zone}[/]]")
            
            res.append(Text.from_markup(f"[{base_color}]{formatted_line}[/]"))
            res.append("\n")

        if self.active_connections:
            conn_text = " ".join([f"{c[0]}→{c[1]}" for c in self.active_connections[-1:]])
            res.append(Text(f" {conn_text}", style=f"bold {pulse_color}"))
        return res

class ProtocolChart(Static):
    PROTO_COLORS_DARK = {
        "TCP": "#FFA500", "UDP": "#FF8C00", "TLS": "#FF7F50", "HTTP": "#FF6600", "DNS": "#D1D5DB", "ICMP": "#FF4500", "ARP": "#6B7280",
    }
    PROTO_COLORS_LIGHT = {
        "TCP": "#EA580C", "UDP": "#C2410C", "TLS": "#F97316", "HTTP": "#FB923C", "DNS": "#4B5563", "ICMP": "#991B1B", "ARP": "#9CA3AF",
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data: dict = {}

    def update_data(self, data: dict) -> None:
        self.data = data
        self.refresh()

    def render(self) -> Text:
        is_dark = getattr(self.app, "dark_mode", True)
        colors = self.PROTO_COLORS_DARK if is_dark else self.PROTO_COLORS_LIGHT
        
        if not self.data:
            return Text("Attente de données...", style="#525252" if is_dark else "#9CA3AF")
        res = Text()
        sorted_proto = sorted(self.data.items(), key=lambda x: x[1], reverse=True)[:5]
        for proto, pct in sorted_proto:
            color = colors.get(proto, "#D1D5DB" if is_dark else "#4B5563")
            bar_len = int(pct / 5)
            res.append(f"{proto:4} ", style=f"bold {color}")
            res.append("#" * bar_len, style=color)
            res.append(f" {pct:4.1f}%\n", style="#6B7280" if is_dark else "#9CA3AF")
        return res

class BandwidthGauge(Static):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._last_val: int = 0
        self._last_time: float = time.time()
        self.current_bps: float = 0.0

    def update_bps(self, total_bytes: int) -> None:
        now = time.time()
        dt = now - self._last_time
        if dt >= 1.0:
            self.current_bps = ((total_bytes - self._last_val) * 8) / (dt * 1_048_576)
            self._last_val = total_bytes
            self._last_time = now
        self.refresh()

    def render(self) -> Text:
        is_dark = getattr(self.app, "dark_mode", True)
        color = "#FF6600" if self.current_bps < 10 else ("#FF4500" if self.current_bps < 50 else "#FF0000")
        if not is_dark: color = "#EA580C" if self.current_bps < 10 else "#991B1B"
        return Text.from_markup(f"TRAFIC: [b {color}]{self.current_bps:.2f} Mbps[/]")

class TopStats(Static):
    def compose(self) -> ComposeResult:
        with Horizontal(id="top_stats_container"):
            with Vertical(id="map_container"):
                yield GeoMap(id="geo_map")
            with Vertical(id="stats_center"):
                with Horizontal(id="cards_container"):
                    yield StatsCard("PPS", "pps_card", classes="stat_card")
                    yield StatsCard("Flows", "flows_card", classes="stat_card")
                    yield StatsCard("Uptime", "uptime_card", classes="stat_card")
                yield PPSGraph(id="pps_graph")
            with Vertical(id="proto_chart_container"):
                yield ProtocolChart(id="proto_chart")
                yield BandwidthGauge(id="bw_gauge")
