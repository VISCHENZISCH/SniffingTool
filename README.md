# SniffingTool Network 

`SniffingTool` est un analyseur de trafic réseau haute performance avec une interface TUI (Terminal User Interface) ultra-moderne, conçu pour les experts en cybersécurité et les administrateurs réseau.


### Performance & Stabilité
- **Multi-threading** : Capture non-bloquante via Scapy.
- **Gestion Mémoire** : Buffer glissant pour éviter la saturation de la RAM.
- **Filtrage BPF Natif** : Utilisez la syntaxe standard (ex: `tcp port 443`) pour un filtrage ultra-rapide.

## Installation

### Prérequis
- Python 3.9+
- Privilèges `root` ou `sudo` (requis pour l'accès aux interfaces réseau).

### Installation Express
```bash
# 1. Cloner et configurer l'environnement
python3 -m venv .venv
source .venv/bin/activate

# 2. Dépendances
pip install -r requirements.txt
```

## Utilisation

Lancez le terminal avec les droits administrateur :

```bash
sudo .venv/bin/python analyzer_ui.py
```

### Raccourcis Clavier
- `s` : **Start/Stop** :: Activer ou désactiver le bouclier de capture.
- `c` : **Clear** :: Effacer l'historique des paquets et les alertes.
- `f` : **Filter** :: Focus sur la barre de filtrage BPF.
- `q` : **Quit** :: Quitter proprement le terminal.


