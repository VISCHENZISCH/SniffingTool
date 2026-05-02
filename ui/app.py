"""
Couche 4 — NetworkAnalyzerApp
Interface SOC avancée avec Deep Packet Inspection (HTTP Headers, Credentials).
"""
import json
import time
import textwrap
import re

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import DataTable, Footer, Input, Label, Log, Tree, TabbedContent, TabPane
from textual.reactive import reactive
from rich.text import Text
from scapy.all import raw, IP, TCP, UDP, Raw
from scapy.layers import http

from core.sniffer import BackendSniffer
from ui.widgets import TopStats


class NetworkAnalyzerApp(App):
    TITLE = "Packet Phantom"
    
    dark_mode = reactive(True)
    search_mode = reactive(False)
    follow_tuple = reactive(None)

    CSS = """
    .dark-theme { background: #050505; color: #D1D5DB; }
    .dark-theme #top_stats_container { background: #121212; border-bottom: solid #222222; }
    .dark-theme DataTable { background: #050505; color: #D1D5DB; }
    .dark-theme DataTable > .datatable--header { background: #161616; color: #FF6600; }
    
    .light-theme { background: #F3F4F6; color: #1F2937; }
    .light-theme #top_stats_container { background: #FFFFFF; border-bottom: solid #E5E7EB; }
    .light-theme DataTable { background: #FFFFFF; color: #1F2937; }
    .light-theme DataTable > .datatable--header { background: #E5E7EB; color: #EA580C; }

    #top_stats_container { height: 12; padding: 1 2; layout: horizontal; }
    #map_container { width: 30%; border-right: solid #222222; align: center middle; }
    #stats_center { width: 40%; padding: 0 2; align: center middle; }
    #cards_container { height: 6; layout: horizontal; align: center middle; }
    .stat_card { width: 33%; height: 100%; margin: 0 1; }
    #pps_graph { height: 3; margin-top: 1; content-align: center middle; }
    #proto_chart_container { width: 30%; padding-left: 2; border-left: solid #222222; }
    #proto_chart { height: 6; }
    #bw_gauge { margin-top: 1; color: #FF6600; }

    DataTable { height: 1fr; border: none; }
    DataTable > .datatable--header { text-style: bold; }
    DataTable > .datatable--cursor { background: #FF660033; color: #FFA500; border-left: solid #FF6600; }

    #details_container { height: 35%; border-top: solid #222222; }
    #packet_tree, #hex_view { padding: 1 2; }
    #filter_container { height: 3; background: #121212; border-top: solid #222222; layout: horizontal; align: center middle; }
    
    Input { background: #000000; border: solid #222222; color: #FFA500; width: 100%; }
    #search_indicator { color: #FF6600; text-style: bold; margin-right: 1; }
    
    Footer { background: #121212; color: #6B7280; }
    """

    BINDINGS = [
        ("q", "quit",            "Quitter"),
        ("s", "toggle_sniffing", "Démarrer/Arrêter"),
        ("c", "clear",           "Effacer"),
        ("f", "focus_filter",    "Filtre/Recherche"),
        ("t", "toggle_theme",    "Dark/Light"),
        ("m", "toggle_mode",     "BPF/Table"),
        ("l", "follow_stream",   "Suivre Stream"),
    ]

    def __init__(self):
        super().__init__()
        self.sniffer = BackendSniffer()
        self.sniffing_active = False
        self.total_bytes = 0
        self.packets: list = [] 
        self.start_time = time.time()
        self.geoip_cache: dict = {}

        from concurrent.futures import ThreadPoolExecutor
        self._geo_executor = ThreadPoolExecutor(max_workers=4)
        self._geo_pending: dict = {}

    def compose(self) -> ComposeResult:
        yield TopStats()
        with Container(id="list_container"):
            yield DataTable(id="packet_table")
        with Container(id="details_container"):
            with TabbedContent():
                with TabPane("ARBORESCENCE"):    yield Tree("Paquet", id="packet_tree")
                with TabPane("HEXADÉCIMAL"):     yield Log(id="hex_view")
        with Horizontal(id="filter_container"):
            yield Label("BPF", id="search_indicator")
            yield Input(placeholder="Filtre Scapy (BPF)", id="filter_input")
        yield Footer()

    def on_mount(self) -> None:
        self.add_class("dark-theme")
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        # Nouvelles colonnes selon spécifications
        table.add_columns("ID", "HEURE", "GEO", "SOURCE", "DST", "OS", "PROTO", "FLAGS", "SIZE", "TTL", "SESSION", "INFOS")
        self.set_interval(0.1, self._update_ui)
        self.set_interval(1.0, self._update_stats)

    def action_toggle_theme(self) -> None:
        self.dark_mode = not self.dark_mode
        self.remove_class("light-theme") if self.dark_mode else self.add_class("light-theme")
        self.add_class("dark-theme") if self.dark_mode else self.remove_class("dark-theme")

    def action_toggle_mode(self) -> None:
        self.search_mode = not self.search_mode
        self.query_one("#search_indicator").update("SEARCH" if self.search_mode else "BPF")

    def action_follow_stream(self) -> None:
        table = self.query_one(DataTable)
        if table.cursor_row is not None:
            # On récupère le paquet via son ID (key de la ligne)
            key = table.get_row_at(table.cursor_row)[0] # Première colonne = ID
            p = next((pkt for pkt in self.packets if str(pkt['id']) == str(key)), None)
            if p and TCP in p['raw'] and IP in p['raw']:
                pkt = p['raw']
                self.follow_tuple = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                self.notify(f"Stream: {self.follow_tuple}")
            else: self.notify("TCP requis", severity="warning")

    def action_toggle_sniffing(self) -> None:
        if self.sniffing_active:
            self.sniffer.stop()
            self.sniffing_active = False
        else:
            f_val = self.query_one("#filter_input").value if not self.search_mode else None
            self.sniffer.start(filter_exp=f_val or None)
            self.sniffing_active = True

    def action_focus_filter(self) -> None:
        self.query_one("#filter_input").focus()

    def action_clear(self) -> None:
        self.query_one(DataTable).clear()
        self.packets.clear()
        self.total_bytes = 0
        self.follow_tuple = None

    def _update_ui(self) -> None:
        search_val = self.query_one("#filter_input").value.lower() if self.search_mode else ""
        for _ in range(50):
            if self.sniffer.display_queue.empty(): break
            pkt_data = self.sniffer.display_queue.get()
            self.total_bytes += pkt_data['length']
            self.packets.append(pkt_data)
            if len(self.packets) > 1000: self.packets.pop(0)

            if self.search_mode and search_val:
                if not any(search_val in str(v).lower() for k, v in pkt_data.items() if k != 'raw'):
                    continue
            
            if self.follow_tuple:
                raw_pkt = pkt_data['raw']
                if TCP in raw_pkt and IP in raw_pkt:
                    cur = (raw_pkt[IP].src, raw_pkt[TCP].sport, raw_pkt[IP].dst, raw_pkt[TCP].dport)
                    rev = (raw_pkt[IP].dst, raw_pkt[TCP].dport, raw_pkt[IP].src, raw_pkt[TCP].sport)
                    if cur != self.follow_tuple and rev != self.follow_tuple: continue
                else: continue

            self._add_to_table(pkt_data)

    def _add_to_table(self, pkt_data):
        table = self.query_one(DataTable)
        s_code, s_geo = self._get_geo(pkt_data['source'])
        d_code, d_geo = self._get_geo(pkt_data['destination'])
        
        # Pulsation carte (Source et Trajet)
        geo_map = self.query_one("#geo_map")
        if s_code != "??": geo_map.pulse_zone(s_code)
        if s_code != "??" and d_code != "??": geo_map.pulse_connection(s_code, d_code)
        
        # Mapping Couleurs selon image utilisateur
        proto = pkt_data['protocol']
        proto_colors = {"TCP": "#FFCC44", "UDP": "#FF8C00", "TLS": "#FF6644", "HTTP": "#FF6600", "DNS": "#888888", "ICMP": "#FF4500"}
        proto_styled = f"[{proto_colors.get(proto, '#D1D5DB')}]{proto}[/]"

        table.add_row(
            Text(str(pkt_data['id']), style="#445588"),
            Text(pkt_data['timestamp'], style="#88AACC"),
            Text(s_geo, style="#66BBAA"),
            Text(pkt_data['source'][:16], style="#CCDDEE"),
            Text(pkt_data['destination'][:16], style="#FF6688"),
            Text(pkt_data['os'], style="#88BB88"),
            Text.from_markup(proto_styled),
            Text(pkt_data['flags'], style="#FFEE66"),
            Text(f"{pkt_data['length']} B", style="#888888"),
            Text(str(pkt_data['ttl']), style="#77BBDD"),
            Text(f"#{pkt_data['session']:04x}" if isinstance(pkt_data['session'], int) else "----", style="#BB88FF"),
            Text(pkt_data['info'][:60], style="#DD8844"),
            key=str(pkt_data['id'])
        )
        if len(table.rows) > 500:
            try: table.remove_row(list(table.rows.keys())[0])
            except: pass

    def _update_stats(self) -> None:
        pps = self.sniffer.stats.pps_history[-1] if self.sniffer.stats.pps_history else 0
        uptime = int(time.time() - self.start_time)
        self.query_one("#pps_card").update_value(f"{pps}")
        self.query_one("#flows_card").update_value(f"{len(self.sniffer.stats.source_ips)}")
        self.query_one("#uptime_card").update_value(f"{uptime//3600:02}:{(uptime%3600)//60:02}:{uptime%60:02}")
        self.query_one("#pps_graph").update_history(self.sniffer.stats.pps_history)
        self.query_one("#bw_gauge").update_bps(self.total_bytes)
        self.query_one("#proto_chart").update_data(self.sniffer.stats.proto_dist)

        # Mise à jour asynchrone du GEO dans le tableau
        table = self.query_one(DataTable)
        # On utilise une copie des clés pour éviter les erreurs si des lignes sont supprimées
        for row_key in list(table.rows.keys()):
            try:
                # GEO est à l'index 2 (ID=0, HEURE=1, GEO=2)
                geo_cell = table.get_cell(row_key, table.columns[2].key)
                if str(geo_cell) == "...":
                    p = next((pkt for pkt in self.packets if str(pkt['id']) == str(row_key)), None)
                    if p:
                        code, geo = self._get_geo(p['source'])
                        if geo != "...":
                            table.update_cell(row_key, table.columns[2].key, Text(geo, style="#66BBAA"))
                            if code != "??": self.query_one("#geo_map").pulse_zone(code)
            except (KeyError, Exception):
                continue

    def _show_details(self, pkt_data: dict) -> None:
        tree = self.query_one("#packet_tree", Tree)
        tree.clear()
        tree.root.label = f"PAQUET #{pkt_data['id']} : {pkt_data['summary']}"
        
        # 1. Analyse Deep Inspection (Credentials / Sensitive)
        raw_pkt = pkt_data['raw']
        if Raw in raw_pkt:
            payload = raw_pkt[Raw].load.decode(errors='ignore')
            sensitive = ["user", "pass", "login", "admin", "pwd", "token", "key", "auth"]
            for word in sensitive:
                if word in payload.lower():
                    node = tree.root.add(f"[bold #EF4444] ALERTE : Donnée sensible détectée ({word})[/]")
                    node.add(f"[#EF4444]{textwrap.fill(payload, 60)}[/]")
                    break

        # 2. Construction de l'arborescence par couche
        layer = raw_pkt
        while layer:
            layer_name = layer.name
            node = tree.root.add(Text.from_markup(f"[bold #FF6600]{layer_name}[/]"))
            
            # Cas spécial HTTP : Headers et Données de Formulaire
            if layer_name == "HTTP Request":
                # Affichage des Headers
                headers_node = node.add("[#FFA500]HEADERS[/]")
                for k, v in layer.fields.items():
                    if k not in ["Method", "Path", "Http_Version"]:
                        val = v.decode() if isinstance(v, bytes) else str(v)
                        headers_node.add(f"{k}: [#D1D5DB]{textwrap.fill(val, 50)}[/]")
                
                # Tentative de capture du corps POST s'il est dans la même couche
                if hasattr(layer, "load") and layer.load:
                    body_node = node.add("[bold #00FF88]CORPS DE LA REQUÊTE (POST DATA)[/]")
                    body_node.add(f"[#00FF88]{textwrap.fill(layer.load.decode(errors='ignore'), 60)}[/]")

            elif layer_name == "HTTP Response":
                headers_node = node.add("[#FFA500]HEADERS[/]")
                for k, v in layer.fields.items():
                    if k not in ["Status_Code", "Reason_Phrase", "Http_Version"]:
                        val = v.decode() if isinstance(v, bytes) else str(v)
                        headers_node.add(f"{k}: [#D1D5DB]{textwrap.fill(val, 50)}[/]")

            # cas RAW : 
            elif layer_name == "Raw":
                payload = layer.load.decode(errors='ignore')
                if any(c.isprintable() for c in payload):
                    node.add(f"[#00FF88]Texte détecté: {textwrap.fill(payload, 60)}[/]")
            
            # Champs standards
            for field in layer.fields_desc:
                try:
                    val = layer.getfieldval(field.name)
                    if val is not None and field.name not in ["load"]: # load déjà géré
                        val_str = textwrap.fill(str(val), width=50)
                        node.add(f"{field.name}: [#D1D5DB]{val_str}[/]")
                except: pass
            
            layer = layer.payload
            if not layer or layer.name == "NoPayload": break
        
        tree.root.expand_all()

        # Hex View
        hex_view = self.query_one("#hex_view", Log)
        hex_view.clear()
        data = raw(raw_pkt)
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_view.write(f"[#6B7280]{i:04x}[/]  [#FF6600]{hex_part:<48}[/]  [#D1D5DB]{asc_part}[/]")

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        # On utilise le row_key qui contient l'ID du paquet
        pkt_id = message.row_key.value
        # Recherche précise dans l'historique
        p = next((pkt for pkt in self.packets if str(pkt['id']) == str(pkt_id)), None)
        if p: self._show_details(p)

    def _query_geo(self, ip: str) -> tuple[str, str, str]:
        import requests
        if ip.startswith(("192.168.", "10.", "172.16.", "127.", "::1")): return ip, "LOCAL", "LOCAL"
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=1.5).json()
            code = r.get("countryCode", "??")
            city = r.get("city", "")
            region = r.get("regionName", "")
            
            # Format: [CODE] City, Region
            display = f"[{code}] {city}" if city else f"[{code}]"
            return ip, code, display
        except: return ip, "??", "UNK"

    def _get_geo(self, ip: str) -> tuple[str, str]:
        if ip in self.geoip_cache: return self.geoip_cache[ip]
        if ip in self._geo_pending:
            fut = self._geo_pending[ip]
            if fut.done():
                _, code, text = fut.result()
                self.geoip_cache[ip] = (code, text)
                del self._geo_pending[ip]
                return code, text
            return "??", "..."
        self._geo_pending[ip] = self._geo_executor.submit(self._query_geo, ip)
        return "??", "..."
