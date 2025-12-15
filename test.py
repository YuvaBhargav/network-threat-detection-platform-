from scapy.all import sniff

def pkt(pkt):
    print(pkt.summary())

print("Sniffing... Press Ctrl+C")
sniff(prn=pkt, store=False)
