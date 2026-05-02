# PacketPhantom - Premium SOC Dashboard

PacketPhantom est un analyseur réseau TUI (Terminal User Interface) haute performance conçu pour le monitoring SOC, combinant une esthétique **Cyber-Punk** agressive et des fonctionnalités de **Deep Packet 

## Fonctionnalités Clés

- **Dashboard "Cyber Skull"** : Visualisation du mouvement des paquets sur une carte mondiale stylisée en forme de crâne.
- **Deep Packet Inspection (DPI)** :
    - Analyse complète des couches (Ethernet, IP, TCP/UDP, HTTP, TLS).
    - Extraction automatique des **Headers HTTP** et des **Bannières de Service**.
    - Détection intelligente de **données sensibles** (credentials, tokens) en clair.
- **Passive OS Fingerprinting** : Identification de l'OS distant via l'analyse du TTL et de la Window Size TCP.
- **Géolocalisation Asynchrone** : Tracking géographique (Pays, Ville) en temps réel avec mise à jour dynamique du tableau.
- **Moteur de Recherche & Filtrage** :
    - Filtrage BPF (Berkeley Packet Filter) à la capture.
    - Recherche textuelle instantanée dans le tableau des paquets.
- **TCP Stream Following** : Isolation et suivi de sessions TCP spécifiques.
- **Esthétique Premium** : Thème Dark/Light alternable (Touche `T`) avec une palette de couleurs calibrée pour la lisibilité SOC.

## Installation

### Linux (Recommandé)
```bash
chmod +x setup.sh
./setup.sh
```

### Windows
1. Installez [Npcap](https://nmap.org/npcap/).
2. Lancez `setup.bat`.

## Utilisation

### Linux
```bash
sudo ./run.sh
```

### Windows (Lancer en tant qu'Administrateur)
```bash
run.bat
```

## Raccourcis Clavier

- `S` : Démarrer / Arrêter la capture.
- `F` : Focus sur la barre de recherche/filtre.
- `M` : Basculer entre le mode Filtrage BPF (Scapy) et Recherche (Tableau).
- `T` : Alterner entre le thème Sombre et Clair.
- `L` : Suivre le flux TCP (Stream Follow) du paquet sélectionné.
- `C` : Effacer l'historique actuel.
- `Q` : Quitter.

## Licence
MIT License. Usage éducatif uniquement.
