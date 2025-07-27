import threading
import time
from scapy.all import sniff, IP, TCP, Raw, send
from scapy.layers.inet import TCP, IP
import subprocess
import atexit
import sys

# ターゲットIP
target_ip = "204.141.172.10"
src_port1 = int(sys.argv[2])
dst_port1 = int(sys.argv[1])
src_port2 = int(sys.argv[4])
dst_port2 = int(sys.argv[3])
# 11531 : 0400 1627
# 11539 : 0400 58c3

# sniffで得た最新のTCP情報を保存するグローバル変数
latest_tcp_info1 = {
    'src_ip': None,
    'dst_ip': None,
    'sport': None,
    'dport': None,
    'seq': None,
    'ack': None,
    'psh_sent': False
}

latest_tcp_info2 = {
    'src_ip': None,
    'dst_ip': None,
    'sport': None,
    'dport': None,
    'seq': None,
    'ack': None,
    'psh_sent': False
}


# iptablesルールを設定
def setup_iptables():
    # # 204.141.172.10宛のACKパケットとPSH-ACKパケットをドロップ
    # # ACKフラグのみのパケットをドロップ
    # subprocess.run([
    #     "iptables", "-A", "OUTPUT",
    #     "-p", "tcp",
    #     "-d", target_ip,
    #     "--tcp-flags", "ALL", "ACK",
    #     "-j", "DROP"
    # ], check=True)
    
    # # PSH-ACKフラグのパケットをドロップ
    # subprocess.run([
    #     "iptables", "-A", "OUTPUT",
    #     "-p", "tcp",
    #     "-d", target_ip,
    #     "--tcp-flags", "ALL", "PSH,ACK",
    #     "-j", "DROP"
    # ], check=True)
    
    # 204.141.172.10からのパケットを他のインターフェースに転送しないようにする
    # FORWARD: ACK, RST, FINいずれかのフラグが立っているパケットをドロップ
    # Only add rules for (src_port1, dst_port1) and (src_port2, dst_port2)
    for dport, sport  in [(src_port1, dst_port1), (src_port2, dst_port2)]:
        # for flag, flagstr in [("SYN", "SYN"), ("ACK", "ACK"), ("ACK,PSH", "ACK,PSH"), ("RST", "RST"), ("FIN", "FIN")]:
        for flag, flagstr in [("ACK", "ACK"), ("ACK,PSH", "ACK,PSH"), ("RST", "RST"), ("FIN,PSH,ACK", "FIN,PSH,ACK"), ("FIN,ACK", "FIN,ACK")]:
            subprocess.run([
                "iptables", "-I", "FORWARD",
                "-p", "tcp",
                "-d", target_ip,
                "--sport", str(sport),
                "--dport", str(dport),
                "--tcp-flags", "ALL", flagstr,
                "-j", "DROP"
            ], check=True)

    print("✅ Packet dropping rules installed")

# プログラム終了時にiptablesルールを削除
def cleanup_iptables():
    try:
        # # 追加したルールを削除
        # # ACKフラグのみのパケットのルールを削除
        # subprocess.run([
        #     "iptables", "-D", "OUTPUT",
        #     "-p", "tcp",
        #     "-d", target_ip,
        #     "--tcp-flags", "ALL", "ACK",
        #     "-j", "DROP"
        # ], check=True)
        
        # # PSH-ACKフラグのパケットのルールを削除
        # subprocess.run([
        #     "iptables", "-D", "OUTPUT",
        #     "-p", "tcp",
        #     "-d", target_ip,
        #     "--tcp-flags", "ALL", "PSH,ACK",
        #     "-j", "DROP"
        # ], check=True)
        
        # Only remove rules for (src_port1, dst_port1) and (src_port2, dst_port2)
        for dport, sport  in [(src_port1, dst_port1), (src_port2, dst_port2)]:
            # for flag, flagstr in [("SYN", "SYN"), ("ACK", "ACK"), ("ACK,PSH", "ACK,PSH"), ("RST", "RST"), ("FIN", "FIN")]:
            for flag, flagstr in [("ACK", "ACK"), ("ACK,PSH", "ACK,PSH"), ("RST", "RST"), ("FIN,PSH,ACK", "FIN,PSH,ACK"), ("FIN,ACK", "FIN,ACK")]:
                subprocess.run([
                    "iptables", "-D", "FORWARD",
                    "-p", "tcp",
                    "-d", target_ip,
                    "--sport", str(sport),
                    "--dport", str(dport),
                    "--tcp-flags", "ALL", flagstr,
                    "-j", "DROP"
                ], check=True)
        print("✅ Packet dropping rules removed")
    except subprocess.CalledProcessError:
        print("⚠️ Error removing iptables rules")
    
    print("✅ Packet dropping rules removed")

# 初期設定
setup_iptables()
atexit.register(cleanup_iptables)

def packet_callback(pkt):
    if IP in pkt and TCP in pkt and pkt[IP].src == target_ip:
        # Only process if (sport==src_port1 and dport==dst_port1) or (sport==src_port2 and dport==dst_port2)
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if (sport == src_port1 and dport == dst_port1) or (sport == src_port2 and dport == dst_port2):
            print(f"\n📦 Received packet from {target_ip}:")
            print(f"🔸 Source Port: {sport}")
            print(f"🔸 Destination Port: {dport}")
            print(f"🔸 Sequence Number: {pkt[TCP].seq}")

            # ペイロードの表示
            if Raw in pkt:
                payload = pkt[Raw].load
                print(f"📄 Payload: {payload.hex()}")

            # 最新のTCP情報を保存
            if sport == src_port1 and dport == dst_port1:
                latest_tcp_info1['src_ip'] = pkt[IP].dst
                latest_tcp_info1['dst_ip'] = pkt[IP].src
                latest_tcp_info1['sport'] = dport
                latest_tcp_info1['dport'] = sport
                latest_tcp_info1['seq'] = pkt[TCP].ack
                latest_tcp_info1['ack'] = pkt[TCP].seq + len(pkt.payload)
            elif sport == src_port2 and dport == dst_port2:
                latest_tcp_info2['src_ip'] = pkt[IP].dst
                latest_tcp_info2['dst_ip'] = pkt[IP].src
                latest_tcp_info2['sport'] = dport
                latest_tcp_info2['dport'] = sport
                latest_tcp_info2['seq'] = pkt[TCP].ack
                latest_tcp_info2['ack'] = pkt[TCP].seq + len(pkt.payload)

            # ACKパケットを作成して送信
            ack_packet = IP(
                src=pkt[IP].dst,
                dst=pkt[IP].src
            )/TCP(
                sport=dport,
                dport=sport,
                seq=pkt[TCP].ack,
                ack=pkt[TCP].seq + len(pkt.payload),
                flags='A'
            )
            print("✅ ACK sent")
            send(ack_packet, verbose=0)

            # 最初のPSH-ACKを即時送信（1回だけ、ポートごとに分岐）
            if sport == src_port1 and dport == dst_port1 and not latest_tcp_info1.get('psh_sent'):
                psh_packet = IP(src=latest_tcp_info1['src_ip'], dst=latest_tcp_info1['dst_ip'])/TCP(
                    sport=latest_tcp_info1['sport'],
                    dport=latest_tcp_info1['dport'],
                    seq=latest_tcp_info1['seq'],
                    ack=latest_tcp_info1['ack'],
                    flags='PA')/Raw(load=bytes.fromhex("04001627"))
                send(psh_packet, verbose=0)
                print(f"[+] First PSH-ACK sent to {latest_tcp_info1['dst_ip']}:{latest_tcp_info1['dport']}")
                latest_tcp_info1['psh_sent'] = True
            elif sport == src_port2 and dport == dst_port2 and not latest_tcp_info2.get('psh_sent'):
                psh_packet = IP(src=latest_tcp_info2['src_ip'], dst=latest_tcp_info2['dst_ip'])/TCP(
                    sport=latest_tcp_info2['sport'],
                    dport=latest_tcp_info2['dport'],
                    seq=latest_tcp_info2['seq'],
                    ack=latest_tcp_info2['ack'],
                    flags='PA')/Raw(load=bytes.fromhex("040058c3"))
                send(psh_packet, verbose=0)
                print(f"[+] First PSH-ACK sent to {latest_tcp_info2['dst_ip']}:{latest_tcp_info2['dport']}")
                latest_tcp_info2['psh_sent'] = True

# タイムスロットでPSH-ACKを送信
def periodic_psh_sender1():
    # sniffでACK送信が行われるまで待機（両方）
    while (latest_tcp_info1['src_ip'] is None or not latest_tcp_info1.get('psh_sent')):
        time.sleep(0.1)
    while True:
        # 11531
        if latest_tcp_info1['psh_sent']:
            time.sleep(15)
            psh_packet1 = IP(src=latest_tcp_info1['src_ip'], dst=latest_tcp_info1['dst_ip'])/TCP(
                sport=latest_tcp_info1['sport'],
                dport=latest_tcp_info1['dport'],
                seq=latest_tcp_info1['seq'],
                ack=latest_tcp_info1['ack'],
                flags='PA')/Raw(load=bytes.fromhex("04001627"))
            send(psh_packet1, verbose=0)
            print(f"[+] Periodic PSH-ACK sent to {latest_tcp_info1['dst_ip']}:{latest_tcp_info1['dport']}")

def periodic_psh_sender2():
    # sniffでACK送信が行われるまで待機（両方）
    while (latest_tcp_info2['src_ip'] is None or not latest_tcp_info2.get('psh_sent')):
        time.sleep(0.1)
    while True:
        # 11539
        if latest_tcp_info2['psh_sent']:
            time.sleep(15)
            psh_packet2 = IP(src=latest_tcp_info2['src_ip'], dst=latest_tcp_info2['dst_ip'])/TCP(
                sport=latest_tcp_info2['sport'],
                dport=latest_tcp_info2['dport'],
                seq=latest_tcp_info2['seq'],
                ack=latest_tcp_info2['ack'],
                flags='PA')/Raw(load=bytes.fromhex("040058c3"))
            send(psh_packet2, verbose=0)
            print(f"[+] Periodic PSH-ACK sent to {latest_tcp_info2['dst_ip']}:{latest_tcp_info2['dport']}")

# バックグラウンドでタイムスロット送信を開始
threading.Thread(target=periodic_psh_sender1, daemon=True).start()
threading.Thread(target=periodic_psh_sender2, daemon=True).start()

        
print(f"🔍 Capturing packets from {target_ip} on enp1s0... (Press Ctrl+C to stop)")
# パケットをキャプチャ (パケットは自動的に破棄される)
sniff(iface="enp1s0", filter=f"tcp and ip src {target_ip}", prn=packet_callback, store=0)
