
import sys
import os
import time
from scapy.all import IP, TCP, Raw, Ether

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.sniffer import BackendSniffer

def test_logic():
    print("[*] Testing PacketPhantom Logic...")
    sniffer = BackendSniffer(interface="lo")
    
    # Mocking packets
    print("[*] Simulating packets...")
    
    # 1. Linux-like packet
    p1 = Ether()/IP(src="192.168.1.5", ttl=64)/TCP(sport=1234, dport=80)
    
    # 2. Windows-like packet
    p2 = Ether()/IP(src="192.168.1.10", ttl=128)/TCP(sport=445, dport=445, window=8192)
    
    # 3. HTTP Request to Metasploitable
    from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
    p3 = Ether()/IP(src="10.30.56.1", dst="10.30.56.120")/TCP(sport=12345, dport=80)/HTTP()/HTTPRequest(Method=b"GET", Host=b"10.30.56.120", Path=b"/index.php", User_Agent=b"Mozilla/5.0 (PacketPhantom)")
    
    # 3.5 HTTP Response from Metasploitable
    p3_resp = Ether()/IP(src="10.30.56.120", dst="10.30.56.1")/TCP(sport=80, dport=12345)/HTTP()/HTTPResponse(Status_Code=b"200", Reason_Phrase=b"OK", Server=b"Apache/2.2.8 (Ubuntu) DAV/2")
    
    # 4. Banner grabbing packet (SSH)
    p4 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=22, dport=55555)/Raw(load=b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n")

    # Injecting directly into analyzer to test enrichment
    print("[*] Analyzing mock packets...")
    sniffer.running = True # Bypass thread check
    sniffer._analyze_packet(p1)
    sniffer._analyze_packet(p2)
    sniffer._analyze_packet(p3)
    sniffer._analyze_packet(p3_resp)
    sniffer._analyze_packet(p4)

    results = []
    while not sniffer.display_queue.empty():
        results.append(sniffer.display_queue.get())

    print(f"[*] Analysis results: {len(results)} packets processed.")
    
    # Assertions (Visual/Logic)
    for i, res in enumerate(results):
        print(f"\n--- Packet {i+1} ---")
        print(f"Proto: {res['protocol']}")
        print(f"Source: {res['source']}")
        print(f"OS: {res['os']}")
        print(f"Info: {res['info']}")
        if res['ua']: print(f"UA: {res['ua']}")

    # Check OS Detection
    assert results[0]['os'] == "Linux/Unix"
    assert "Windows" in results[1]['os']
    
    # Check Banner Grabbing
    assert "SSH" in results[4]['info']
    
    # Check UA Extraction
    assert "PacketPhantom" in results[2]['ua']
    
    # Check Metasploitable Details
    assert "/index.php" in results[2]['info']
    assert "Apache/2.2.8" in results[3]['info']

    print("\n[+] LOGIC TEST PASSED!")

if __name__ == "__main__":
    try:
        test_logic()
    except Exception as e:
        print(f"[-] TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
