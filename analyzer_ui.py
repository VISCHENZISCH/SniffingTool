from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, Tree, Log, Sparkline, Label, TabbedContent, TabPane, Input
from textual import work, on
from textual.reactive import reactive
import threading
import time
from sniffer import BackendSniffer
from rich.text import Text
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import raw

class MetricGauge(Static):
    def __init__(self, label, value_id, **kwargs):
        super().__init__(**kwargs)
        self.label = label
        self.value_id = value_id

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Label(f"{self.label} [", classes="htop_label")
            yield Label("", id=self.value_id, classes="gauge_bar")
            yield Label("]", classes="htop_label")

class TopStats(Static):
    """Top section resembling htop gauges."""
    def compose(self) -> ComposeResult:
        with Horizontal(id="top_stats_container"):
            with Vertical(classes="stats_column"):
                yield MetricGauge("PKT", "pkt_gauge")
                yield MetricGauge("PPS", "pps_gauge")
            with Vertical(classes="stats_column"):
                yield Label("Tasks: [b]1 sniffer active[/b]", classes="htop_info")
                yield Label("Load average: [b]Real-time[/b]", classes="htop_info")
                yield Label("Uptime: [b]00:00:00[/b]", id="uptime_label", classes="htop_info")

class NetworkAnalyzerApp(App):
    """SniffingTool"""
    
    TITLE = "SniffingTool"
    
    CSS = """
    Screen {
        background: #000000;
        color: #efefef;
    }

    #top_stats_container {
        height: 6;
        padding: 1 2;
        background: #000000;
    }

    .stats_column {
        width: 50%;
    }

    .gauge_bar {
        color: #00ff00;
        width: 32;
    }

    .htop_label {
        color: #ffffff;
        text-style: bold;
    }

    .htop_info {
        color: #00aaaa;
    }

    #list_container {
        height: 1fr;
        background: #000000;
    }

    DataTable {
        height: 100%;
        background: #000000;
        border: none;
    }

    DataTable > .datatable--header {
        background: #00aa00;
        color: #000000;
        text-style: bold;
    }

    DataTable > .datatable--cursor {
        background: #00aaaa;
        color: #000000;
    }

    #details_container {
        height: 30%;
        border-top: solid #555555;
        background: #000000;
    }

    #filter_container {
        height: 3;
        background: #000000;
        border-top: solid #555555;
        padding: 0 1;
        layout: horizontal;
        align: center middle;
    }

    Input {
        background: #000000;
        border: none;
        color: #00ff00;
        width: 100%;
    }

    TabPane {
        padding: 0;
        background: #000000;
    }

    Log, Tree {
        background: #000000;
        color: #ffffff;
    }

    Footer {
        background: #00aaaa;
        color: #000000;
    }
    """

    BINDINGS = [
        ("q", "quit", "F10Quit"),
        ("s", "toggle_sniffing", "F2Start"),
        ("c", "clear", "F4Clear"),
        ("f", "focus_filter", "F3Filter"),
    ]

    def __init__(self):
        super().__init__()
        self.sniffer = BackendSniffer()
        self.sniffing_active = False
        self.packet_count = 0
        self.packets = []
        self.start_time = time.time()

    def compose(self) -> ComposeResult:
        yield TopStats()
        
        with Container(id="list_container"):
            yield DataTable(id="packet_table")
        
        with Container(id="details_container"):
            with TabbedContent():
                with TabPane("TREE"):
                    yield Tree("Packet", id="packet_tree")
                with TabPane("HEX"):
                    yield Log(id="hex_view")
                with TabPane("ALERTS"):
                    yield Log(id="alerts_log")
            
        with Horizontal(id="filter_container"):
             yield Label("FILTER: ", classes="htop_label")
             yield Input(placeholder="BPF syntax (e.g. tcp port 80)", id="filter_input")

        yield Footer()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("ID", "TIME", "SOURCE", "DESTINATION", "PROTO", "INFO")
        
        self.set_interval(0.1, self.update_ui)
        self.set_interval(1.0, self.update_stats)

    def action_toggle_sniffing(self):
        if self.sniffing_active:
            self.sniffer.stop()
            self.sniffing_active = False
            self.notify("SHIELD DEACTIVATED")
        else:
            filter_txt = self.query_one("#filter_input").value
            self.sniffer.start(filter_exp=filter_txt)
            self.sniffing_active = True
            self.notify("SHIELD ACTIVE")

    def action_focus_filter(self):
        self.query_one("#filter_input").focus()

    def action_clear(self):
        self.query_one(DataTable).clear()
        self.packets = []
        self.packet_count = 0
        self.query_one("#alerts_log").clear()

    def update_ui(self):
        for _ in range(30):
            if self.sniffer.display_queue.empty():
                break
            
            packet_data = self.sniffer.display_queue.get()
            self.packet_count += 1
            self.packets.append(packet_data)
            if len(self.packets) > 500: self.packets.pop(0)
            
            table = self.query_one(DataTable)
            
            proto = packet_data['protocol']
            proto_color = "cyan"
            if proto == "TCP": proto_color = "cyan"
            elif proto == "UDP": proto_color = "blue"
            elif proto == "ICMP": proto_color = "magenta"
            elif proto == "HTTP": proto_color = "green"
            
            proto_styled = f"[{proto_color}]{proto}[/]"
            if packet_data.get('alerts'):
                proto_styled = f"[white on red]{proto}[/]"
                for a in packet_data['alerts']:
                    self.query_one("#alerts_log").write(f"!! {a} | {packet_data['source']}")

            table.add_row(
                Text(str(self.packet_count), style="cyan"),
                Text(packet_data['timestamp'], style="bright_black"),
                Text(packet_data['source'], style="white"),
                Text(packet_data['destination'], style="white"),
                Text.from_markup(proto_styled),
                Text(packet_data['info'][:60], style="green"),
                key=str(self.packet_count)
            )
            
            if self.packet_count > 500:
                try: table.remove_row(str(self.packet_count - 500))
                except: pass

    def update_stats(self):
        total = self.sniffer.stats.total_packets
        pps = self.sniffer.stats.pps_history[-1] if self.sniffer.stats.pps_history else 0
        
        # HTOP Gauge style
        def get_gauge(val, max_val=100):
            percent = min(100, (val / max_val) * 100) if max_val > 0 else 0
            bars = int(percent / 3.33)
            return ("|" * bars).ljust(30) + f" {percent:4.1f}%"

        self.query_one("#pkt_gauge").update(get_gauge(total, 5000))
        self.query_one("#pps_gauge").update(get_gauge(pps, 200))
        
        elapsed = int(time.time() - self.start_time)
        hrs, rem = divmod(elapsed, 3600)
        mins, secs = divmod(rem, 60)
        self.query_one("#uptime_label").update(f"Uptime: [b]{hrs:02}:{mins:02}:{secs:02}[/b]")

    def on_data_table_row_selected(self, message: DataTable.RowSelected):
        idx = message.cursor_row
        if 0 <= idx < len(self.packets):
            self.show_details(self.packets[idx])

    def show_details(self, pkt_data):
        tree = self.query_one("#packet_tree", Tree)
        tree.clear()
        tree.root.label = f"FRAME: {pkt_data['summary']}"
        
        raw_pkt = pkt_data['raw']
        current_layer = raw_pkt
        while current_layer:
            node = tree.root.add(f"[cyan]{current_layer.name}[/]")
            for field in current_layer.fields_desc:
                val = current_layer.getfieldval(field.name)
                node.add(f"{field.name}: [green]{val}[/]")
            current_layer = current_layer.payload
            if not current_layer or current_layer.name == "NoPayload": break
        tree.root.expand()
        
        hex_view = self.query_one("#hex_view", Log)
        hex_view.clear()
        hex_data = raw(raw_pkt)
        for i in range(0, len(hex_data), 16):
            chunk = hex_data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_view.write(f"[bright_black]{i:04x}[/]  [cyan]{hex_part:<48}[/]  [green]{ascii_part}[/]")

if __name__ == "__main__":
    app = NetworkAnalyzerApp()
    app.run()
