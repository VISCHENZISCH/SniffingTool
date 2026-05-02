#!/bin/bash
# PacketPhantom - Launcher (Linux)

if [ "$EUID" -ne 0 ]; then 
    echo "[!] PacketPhantom nécessite les privilèges ROOT pour la capture réseau."
    sudo "$0" "$@"
    exit
fi

echo "[*] Démarrage de PacketPhantom..."
.venv/bin/python main.py
