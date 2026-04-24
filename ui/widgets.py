"""
Couche 4 — Widgets Textual
Composants visuels réutilisables pour le dashboard TUI.
"""
import time
from textual.containers import Horizontal, Vertical
from textual.widgets import Static, Label
from textual.app import ComposeResult
from rich.text import Text


class MetricGauge(Static):
    """Jauge de style htop : LABEL [████░░░░] VAL%"""
    def __init__(self, label: str, value_id: str, **kwargs):
        super().__init__(**kwargs)
        self.label = label
        self.value_id = value_id

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Label(f"{self.label} [", classes="htop_label")
            yield Label("", id=self.value_id, classes="gauge_bar")
            yield Label("]", classes="htop_label")


class ProtocolChart(Static):
    """
    Couche 4 — Graphique horizontal temps réel.
    Affiche la répartition des protocoles sous forme de barres colorées.
    """
    PROTO_COLORS = {
        "TCP": "cyan", "UDP": "blue", "TLS": "yellow",
        "HTTP": "green", "DNS": "white", "ICMP": "magenta", "ARP": "bright_black",
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data: dict = {}

    def update_data(self, data: dict) -> None:
        self.data = data
        self.refresh()

    def render(self) -> Text:
        if not self.data:
            return Text("En attente de données...", style="bright_black")
        res = Text()
        sorted_proto = sorted(self.data.items(), key=lambda x: x[1], reverse=True)[:5]
        for proto, pct in sorted_proto:
            color = self.PROTO_COLORS.get(proto, "white")
            bar_len = int(pct / 5)
            res.append(f"{proto:4} ", style="bold")
            res.append("▉" * bar_len, style=color)
            res.append(f" {pct:4.1f}%\n", style="bright_black")
        return res


class BandwidthGauge(Static):
    """
    Couche 4 — Mesure de la bande passante live.
    Affiche le débit courant en Mbps avec code couleur.
    """
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
        color = "green" if self.current_bps < 10 else ("yellow" if self.current_bps < 50 else "red")
        return Text.from_markup(f"TRAFFIC: [b {color}]{self.current_bps:.2f} Mbps[/]")


class TopStats(Static):
    """
    Couche 4 — Bandeau de statistiques global (panel du haut).
    Compose : jauges PKT/PPS, bandwidth, graphique protocoles, menace, uptime.
    """
    def compose(self) -> ComposeResult:
        with Horizontal(id="top_stats_container"):
            with Vertical(classes="stats_column"):
                yield MetricGauge("PKT", "pkt_gauge")
                yield MetricGauge("PPS", "pps_gauge")
                yield BandwidthGauge(id="bw_gauge")
            with Vertical(classes="stats_column"):
                yield ProtocolChart(id="proto_chart")
                yield Label("Uptime: [b]00:00:00[/b]", id="uptime_label", classes="htop_info")
