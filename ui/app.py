"""
Couche 4 — NetworkAnalyzerApp
Application TUI principale (Textual).
Orchestre la capture, l'affichage et les exports.
"""
import json
import time

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import DataTable, Footer, Input, Label, Log, Tree, TabbedContent, TabPane
from rich.text import Text
from scapy.all import raw

from core.sniffer import BackendSniffer
from ui.widgets import TopStats


class NetworkAnalyzerApp(App):
    """
    SniffingTool — Interface TUI principale.
    Raccourcis :
        s  → Start/Stop capture
        f  → Focus filtre BPF
        c  → Clear
        e  → Export PCAP
        j  → Export JSON
        h  → Ouvrir Dashboard web
        q  → Quitter
    """
    TITLE = "SniffingTool — Advanced IDS/TUI"

    CSS = """
    Screen { background: #000000; color: #efefef; }

    #top_stats_container {
        height: 10; padding: 1 2;
        background: #080808; border-bottom: double #00aaaa;
    }
    .stats_column { width: 50%; }
    .gauge_bar    { color: #00ff00; width: 32; }
    .htop_label   { color: #ffffff; text-style: bold; }
    .htop_info    { color: #00aaaa; }
    #proto_chart  { height: 5; }
    #bw_gauge     { margin-top: 1; color: #00aaaa; }

    DataTable { height: 1fr; background: #000000; border: none; }
    DataTable > .datatable--header { background: #00aa00; color: #000000; text-style: bold; }
    DataTable > .datatable--cursor { background: #00aaaa; color: #000000; }

    #details_container {
        height: 35%; border-top: solid #00aaaa; background: #000000;
    }
    #filter_container {
        height: 3; background: #0c0c0c;
        border-top: solid #555555; layout: horizontal; align: center middle;
    }
    Input  { background: #000000; border: none; color: #00ff00; width: 100%; }
    Footer { background: #00aaaa; color: #000000; }
    """

    BINDINGS = [
        ("q", "quit",            "Quit"),
        ("s", "toggle_sniffing", "Start/Stop"),
        ("c", "clear",           "Clear"),
        ("f", "focus_filter",    "Filter"),
        ("e", "export_pcap",     "PCAP"),
        ("j", "export_json",     "JSON"),
    ]

    # ------------------------------------------------------------------ #
    #  Init                                                               #
    # ------------------------------------------------------------------ #
    def __init__(self):
        super().__init__()
        self.sniffer = BackendSniffer()
        self.sniffing_active = False
        self.packet_count = 0
        self.total_bytes = 0
        self.packets: list = []
        self.start_time = time.time()
        self.geoip_cache: dict = {}

        # Résolution Géo-IP non-bloquante
        from concurrent.futures import ThreadPoolExecutor
        self._geo_executor = ThreadPoolExecutor(max_workers=4)
        self._geo_pending: dict = {}

    # ------------------------------------------------------------------ #
    #  Composition                                                        #
    # ------------------------------------------------------------------ #
    def compose(self) -> ComposeResult:
        yield TopStats()
        with Container(id="list_container"):
            yield DataTable(id="packet_table")
        with Container(id="details_container"):
            with TabbedContent():
                with TabPane("TREE"):    yield Tree("Packet", id="packet_tree")
                with TabPane("HEX"):     yield Log(id="hex_view")
        with Horizontal(id="filter_container"):
            yield Label("FILTER: ", classes="htop_label")
            yield Input(placeholder="BPF syntax (ex: tcp port 443)", id="filter_input")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("ID", "TIME", "GEO", "SOURCE", "DESTINATION", "PROTO", "INFO")
        self.set_interval(0.1, self._update_ui)
        self.set_interval(1.0, self._update_stats)


    # ------------------------------------------------------------------ #
    #  Géo-IP non-bloquant                                               #
    # ------------------------------------------------------------------ #
    def _query_geo(self, ip: str) -> tuple[str, str]:
        import requests
        if ip.startswith(("192.168.", "10.", "172.16.", "127.", "::1")):
            return ip, "🏠 LOCAL"
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.5).json()
            country = r.get("countryCode", "??")
            flag = "".join(chr(127397 + ord(c)) for c in country)
            return ip, f"{flag} {country}"
        except Exception:
            return ip, "🌍 UNK"

    def _get_geo(self, ip: str) -> str:
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]
        if ip in self._geo_pending:
            fut = self._geo_pending[ip]
            if fut.done():
                _, result = fut.result()
                self.geoip_cache[ip] = result
                del self._geo_pending[ip]
                return result
            return "⏳ ..."
        self._geo_pending[ip] = self._geo_executor.submit(self._query_geo, ip)
        return "⏳ ..."

    # ------------------------------------------------------------------ #
    #  Actions clavier                                                    #
    # ------------------------------------------------------------------ #
    def action_toggle_sniffing(self) -> None:
        if self.sniffing_active:
            self.sniffer.stop()
            self.sniffing_active = False
            self.notify("BOUCLIER DÉSACTIVÉ", severity="error")
        else:
            filter_txt = self.query_one("#filter_input").value
            self.sniffer.start(filter_exp=filter_txt or None)
            self.sniffing_active = True
            self.notify("BOUCLIER ACTIF", severity="information")

    def action_focus_filter(self) -> None:
        self.query_one("#filter_input").focus()

    def action_clear(self) -> None:
        self.query_one(DataTable).clear()
        self.packets.clear()
        self.packet_count = 0
        self.total_bytes = 0

    def action_export_pcap(self) -> None:
        fn = self.sniffer.export_pcap()
        self.notify(f"PCAP exporté → {fn}")

    def action_export_json(self) -> None:
        fn = f"export_{int(time.time())}.json"
        data = [{k: str(v) for k, v in p.items() if k != 'raw'} for p in self.packets]
        with open(fn, 'w') as f:
            json.dump(data, f, indent=4)
        self.notify(f"JSON exporté → {fn}")



    # ------------------------------------------------------------------ #
    #  Boucles UI (0.1s & 1s)                                            #
    # ------------------------------------------------------------------ #
    def _update_ui(self) -> None:
        """Dépile jusqu'à 30 paquets de la queue d'affichage."""
        for _ in range(30):
            if self.sniffer.display_queue.empty():
                break
            pkt = self.sniffer.display_queue.get()
            self.packet_count += 1
            self.total_bytes += pkt['length']
            self.packets.append(pkt)
            if len(self.packets) > 500:
                self.packets.pop(0)

            table = self.query_one(DataTable)
            geo = self._get_geo(pkt['source'])
            proto = pkt['protocol']
            colors = {"TCP": "cyan", "UDP": "blue", "ICMP": "magenta",
                      "HTTP": "green", "DNS": "white", "TLS": "yellow"}
            styled = f"[{colors.get(proto, 'white')}]{proto}[/]"

            table.add_row(
                Text(str(self.packet_count), style="cyan"),
                Text(pkt['timestamp'],        style="bright_black"),
                Text(geo),
                Text(pkt['source'][:16],      style="white"),
                Text(pkt['destination'][:16], style="white"),
                Text.from_markup(styled),
                Text(pkt['info'][:60],        style="green"),
                key=str(self.packet_count),
            )
            if self.packet_count > 500:
                try:
                    table.remove_row(str(self.packet_count - 500))
                except Exception:
                    pass

    def _update_stats(self) -> None:
        """Met à jour les jauges, le graphique protocoles et le score de menace."""
        total = self.sniffer.stats.total_packets
        pps   = self.sniffer.stats.pps_history[-1] if self.sniffer.stats.pps_history else 0

        self.query_one("#pkt_gauge").update(
            ("|" * int(min(100, total / 1000) / 3.125)).ljust(32) + f" {total}"
        )
        self.query_one("#pps_gauge").update(
            ("|" * int(min(100, pps / 10) / 3.125)).ljust(32) + f" {pps}"
        )
        self.query_one("#bw_gauge").update_bps(self.total_bytes)
        self.query_one("#proto_chart").update_data(self.sniffer.stats.proto_dist)

        elapsed = int(time.time() - self.start_time)
        h, rem = divmod(elapsed, 3600)
        m, s  = divmod(rem, 60)
        self.query_one("#uptime_label").update(f"Uptime: [b]{h:02}:{m:02}:{s:02}[/b]")

    # ------------------------------------------------------------------ #
    #  Détail paquet (TREE + HEX)                                        #
    # ------------------------------------------------------------------ #
    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        idx = message.cursor_row
        if 0 <= idx < len(self.packets):
            self._show_details(self.packets[idx])

    def _show_details(self, pkt_data: dict) -> None:
        tree = self.query_one("#packet_tree", Tree)
        tree.clear()
        tree.root.label = f"FRAME: {pkt_data['summary']}"
        raw_pkt = pkt_data['raw']
        layer = raw_pkt
        while layer:
            node = tree.root.add(f"[cyan]{layer.name}[/]")
            for field in layer.fields_desc:
                try:
                    node.add(f"{field.name}: [green]{layer.getfieldval(field.name)}[/]")
                except Exception:
                    pass
            layer = layer.payload
            if not layer or layer.name == "NoPayload":
                break
        tree.root.expand()

        hex_view = self.query_one("#hex_view", Log)
        hex_view.clear()
        data = raw(raw_pkt)
        for i in range(0, len(data), 16):
            chunk    = data[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_view.write(f"[bright_black]{i:04x}[/]  [cyan]{hex_part:<48}[/]  [green]{asc_part}[/]")
