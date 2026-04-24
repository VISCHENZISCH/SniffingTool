# SniffingTool — Network Analyzer

> Analyseur réseau temps réel · Capture, décodage multi-protocoles et visualisation TUI

## Architecture

```
sniffing_tool/
├── main.py              # Point d'entrée unique
│
├── core/                # Couches 1 & 2 — Backend réseau
│   ├── stats.py         # PacketStats (métriques temps réel)
│   └── sniffer.py       # BackendSniffer — Capture + Analyse protocolaire
│
└── ui/                  # Interface TUI (Textual)
    ├── widgets.py       # MetricGauge, ProtocolChart, BandwidthGauge, TopStats
    └── app.py           # NetworkAnalyzerApp
```

## Fonctionnalités

### Couche 1 — Capture Réseau
- **AsyncSniffer Scapy** : capture non-bloquante multi-thread
- **Filtres BPF dynamiques** : syntaxe standard (`tcp port 443`)
- **Export PCAP** : buffer de 2000 paquets, export Wireshark (touche `e`)

### Couche 2 — Analyse Multi-Protocoles
- **TLS/SNI** : identification des domaines même en HTTPS
- **DNS Inverse** : résolution hostname avec cache
- **HTTP** : extraction verb + host
- **ARP** : suivi de la table IP-MAC
- **HexView coloré** : offset / hex / ASCII dans la TUI

### Interface TUI (Textual)
- **Protocol Chart** : répartition temps réel avec barres colorées
- **Bande passante live** : débit en Mbps avec code couleur
- **Géo-IP non-bloquant** : drapeaux + code pays (ThreadPoolExecutor)
- **HexView & Tree** : inspection couche par couche de chaque paquet
- **Export PCAP & JSON** : raccourcis clavier directs

## Installation

### Prérequis
- Python 3.9+
- Privilèges `root` / `sudo` (accès aux interfaces réseau)

### Installation Express

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Utilisation

```bash
sudo .venv/bin/python main.py
```

### Raccourcis Clavier

| Touche | Action |
|--------|--------|
| `s` | Start / Stop la capture |
| `f` | Focus filtre BPF |
| `c` | Clear la table |
| `e` | Export PCAP (Wireshark) |
| `j` | Export JSON |
| `q` | Quitter |
