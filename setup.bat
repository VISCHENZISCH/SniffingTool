@echo off
echo [*] Installation de PacketPhantom (Windows)
echo [!] NOTE: Npcap doit être installé pour la capture reseau.

python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt

echo [+] Installation terminee !
pause
