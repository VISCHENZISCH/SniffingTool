#!/bin/bash
# PacketPhantom - Installer (Linux)

echo "[*] Installation de PacketPhantom..."

# 1. Dépendances système
echo "[*] Installation des dépendances système (libpcap-dev)..."
sudo apt-get update && sudo apt-get install -y libpcap-dev python3-dev python3-venv

# 2. Création de l'environnement virtuel
if [ ! -d ".venv" ]; then
    echo "[*] Création du virtualenv..."
    python3 -m venv .venv
fi

# 3. Installation des dépendances Python
echo "[*] Installation des dépendances Python..."
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "[+] Installation terminée !"
echo "[*] Pour lancer l'application, utilisez : ./run.sh"
chmod +x run.sh
