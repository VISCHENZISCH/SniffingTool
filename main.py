"""
SniffingTool — Point d'entrée unique
Lancer avec : sudo .venv/bin/python main.py

Architecture :
    Couche 1 → Capture réseau   (core/sniffer.py)
    Couche 2 → Analyse proto    (core/sniffer.py)
    Couche 4 → TUI Textual      (ui/app.py + ui/widgets.py)
"""
from ui.app import NetworkAnalyzerApp

if __name__ == "__main__":
    NetworkAnalyzerApp().run()
