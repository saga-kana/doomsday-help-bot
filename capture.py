import threading
from threading import Lock
import time
from scapy.all import sniff, IP, TCP, Raw, send, RandShort, Ether, sendp
from scapy.layers.inet import TCP, IP
import subprocess
import atexit
import sys, os

# ターゲットIP
remote_mac = "00:00:17:4b:6f:6e"
local_mac = "02:00:17:02:d2:fe"
remote_ip = "204.141.172.10"
local_ip = "10.1.0.92" # enp1s0のIPアドレス
window_size = 65535
ttl = 63
local_port1 = int(sys.argv[1])
remote_port1 = int(sys.argv[2]) # 11531
local_port2 = int(sys.argv[3])
remote_port2 = int(sys.argv[4]) # 11538
# 11531 : 0400 1627
# 11539 : 0400 58c3

primary_ports = [11530, 11531, 11532, 11533, 11534, 11535, 11536, 11537]
secondary_ports = [11538, 11539]

# ACKのタイムスタンプ保存用グローバル変数
primary_ack_ts = {'tsval': None, 'tsecr': None, 'timestamp': None}
secondary_ack_ts = {'tsval': None, 'tsecr': None, 'timestamp': None}

last_help_mtime = None

# help.txtトリガーの0400e228送信管理

help_packet_pending = False
help_packet_seq = None
help_packet_ack = None
help_ack_count = 0  # 0400e228未ACK時の通常ACKカウント
help_ack_count_threshold = 5  # 5回のACKで再送


# sniffで得た最新のTCP情報を保存するグローバル変数
latest_tcp_info_lock = Lock()
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

# ACKカウント（periodic送信制御用）
ack_count1 = 0
ack_count2 = 0


# iptablesルールを設定
def setup_iptables():
    # # 204.141.172.10宛のACKパケットとPSH-ACKパケットをドロップ
    print(local_port1, remote_port1, local_port2, remote_port2)
    
    # 204.141.172.10からのパケットを他のインターフェースに転送しないようにする
    # FORWARD: ACK, RST, FINいずれかのフラグが立っているパケットをドロップ
    # Only add rules for (local_port1, remote_port1) and (local_port2, remote_port2)
    for local_port, remote_port  in [(local_port1, remote_port1), (local_port2, remote_port2)]:
        # for flag, flagstr in [("SYN", "SYN"), ("ACK", "ACK"), ("ACK,PSH", "ACK,PSH"), ("RST", "RST"), ("FIN", "FIN")]:
        # for flag, flagstr in [("ACK,PSH", "ACK"), ("RST", "RST"), ("FIN,PSH,ACK", "FIN,PSH,ACK"), ("FIN,ACK", "FIN,ACK")]:
        # for flag, flagstr in [("ACK", "ACK"), ("RST", "RST"), ("FIN,PSH,ACK", "FIN,PSH,ACK"), ("FIN,ACK", "FIN,ACK")]:
        #     subprocess.run([
        #         "iptables", "-I", "FORWARD",
        #         "-p", "tcp",
        #         "-d", remote_ip,
        #         "--sport", str(local_port),
        #         "--dport", str(remote_port),
        #         "--tcp-flags", flag, flagstr,
        #         "-j", "DROP"
        #     ], check=True)
        subprocess.run([
            "iptables", "-I", "FORWARD",
            "-p", "tcp",
            "-d", remote_ip,
            "--sport", str(local_port),
            "--dport", str(remote_port),
            "-j", "DROP"
        ], check=True)
        subprocess.run([
            "iptables", "-I", "FORWARD",
            "-p", "tcp",
            "-s", remote_ip,
            "--dport", str(local_port),
            "--sport", str(remote_port),
            "-j", "DROP"
        ], check=True)
    
    # for local_port, remote_port  in [(local_port1, remote_port1), (local_port2, remote_port2)]:
    #     # IN
    #     subprocess.run([
    #         "iptables", "-I", "INPUT",
    #         "-p", "tcp",
    #         "-d", local_ip,
    #         "--dport", str(local_port),
    #         "-s", remote_ip,
    #         "--sport", str(remote_port),
    #         "-j", "ACCEPT"
    #     ], check=True)
    #     # OUT
    #     subprocess.run([
    #         "iptables", "-I", "INPUT",
    #         "-p", "tcp",
    #         "-s", local_ip,
    #         "--sport", str(local_port),
    #         "-d", remote_ip,
    #         "--dport", str(remote_port),
    #         "-j", "ACCEPT"
    #     ], check=True)
    print("✅ Packet dropping rules installed")

# プログラム終了時にiptablesルールを削除
def cleanup_iptables():
    try:
        # # 追加したルールを削除
        print(local_port1, remote_port1, local_port2, remote_port2)
        
        # Only remove rules for (local_port1, remote_port1) and (local_port2, remote_port2)
        for local_port, remote_port  in [(local_port1, remote_port1), (local_port2, remote_port2)]:
            # for flag, flagstr in [("SYN", "SYN"), ("ACK", "ACK"), ("ACK,PSH", "ACK,PSH"), ("RST", "RST"), ("FIN", "FIN")]:
            # for flag, flagstr in [("ACK,PSH", "ACK"), ("RST", "RST"), ("FIN,PSH,ACK", "FIN,PSH,ACK"), ("FIN,ACK", "FIN,ACK")]:
            # for flag, flagstr in [("ACK", "ACK"), ("RST", "RST"), ("FIN,PSH,ACK", "FIN,PSH,ACK"), ("FIN,ACK", "FIN,ACK")]:
            #     subprocess.run([
            #         "iptables", "-D", "FORWARD",
            #         "-p", "tcp",
            #         "-d", remote_ip,
            #         "--sport", str(local_port),
            #         "--dport", str(remote_port),
            #         "--tcp-flags", flag, flagstr,
            #         "-j", "DROP"
            #     ], check=True)
            subprocess.run([
                "iptables", "-D", "FORWARD",
                "-p", "tcp",
                "-d", remote_ip,
                "--sport", str(local_port),
                "--dport", str(remote_port),
                "-j", "DROP"
            ], check=True)
            subprocess.run([
                "iptables", "-D", "FORWARD",
                "-p", "tcp",
                "-s", remote_ip,
                "--dport", str(local_port),
                "--sport", str(remote_port),
                "-j", "DROP"
            ], check=True)

        # for local_port, remote_port  in [(local_port1, remote_port1), (local_port2, remote_port2)]:
        #     subprocess.run([
        #         "iptables", "-D", "INPUT",
        #         "-p", "tcp",
        #         "-d", local_ip,
        #         "--dport", str(local_port),
        #         "-s", remote_ip,
        #         "--sport", str(remote_port),
        #         "-j", "ACCEPT"
        #     ], check=True)
        #     subprocess.run([
        #         "iptables", "-D", "INPUT",
        #         "-p", "tcp",
        #         "-s", local_ip,
        #         "--sport", str(local_port),
        #         "-d", remote_ip,
        #         "--dport", str(remote_port),
        #         "-j", "ACCEPT"
        #     ], check=True)
        print("✅ Packet dropping rules removed")
    except subprocess.CalledProcessError:
        print("⚠️ Error removing iptables rules")
    
    print("✅ Packet dropping rules removed")


def packet_callback(pkt):
    with latest_tcp_info_lock:
        if IP in pkt and TCP in pkt and pkt[IP].src == remote_ip:
            # Only process if (sport==local_port1 and dport==remote_port1) or (sport==local_port2 and dport==remote_port2)
            # print(f"🔍 Packet from {pkt[IP].src} to {pkt[IP].dst} on ports {pkt[TCP].sport} -> {pkt[TCP].dport}")
            remote_port = pkt[TCP].sport
            local_port = pkt[TCP].dport
            if (local_port == local_port1 and remote_port == remote_port1) or (local_port == local_port2 and remote_port == remote_port2):
                # print(f"\n📦 Received packet from {target_ip}:")
                # print(f"🔸 Source Port: {sport}")
                # print(f"🔸 Destination Port: {dport}")
                print(f"🔍 Packet from {pkt[IP].src} to {pkt[IP].dst} on ports {pkt[TCP].sport} -> {pkt[TCP].dport}, flags={pkt[TCP].flags}, options={pkt[TCP].options}")

                # ペイロードの表示
                # if Raw in pkt:
                #     payload = pkt[Raw].load
                #     print(f"📄 Payload: {payload.hex()}")

                # 最新のTCP情報を保存
                global latest_tcp_info1
                global latest_tcp_info2
                if local_port == local_port1 and remote_port == remote_port1:
                    latest_tcp_info1['src_ip'] = pkt[IP].dst
                    latest_tcp_info1['dst_ip'] = pkt[IP].src
                    latest_tcp_info1['sport'] = local_port
                    latest_tcp_info1['dport'] = remote_port
                    latest_tcp_info1['seq'] = pkt[TCP].ack
                    latest_tcp_info1['ack'] = pkt[TCP].seq + len(pkt[TCP].payload)
                    latest_tcp_info1['ttl'] = pkt[IP].ttl
                    latest_tcp_info1['ip_options'] = pkt[IP].options
                    latest_tcp_info1['tcp_window'] = pkt[TCP].window if hasattr(pkt[TCP], 'window') else window_size
                    latest_tcp_info1['tcp_options'] = pkt[TCP].options
                elif local_port == local_port2 and remote_port == remote_port2:
                    latest_tcp_info2['src_ip'] = pkt[IP].dst
                    latest_tcp_info2['dst_ip'] = pkt[IP].src
                    latest_tcp_info2['sport'] = local_port
                    latest_tcp_info2['dport'] = remote_port
                    latest_tcp_info2['seq'] = pkt[TCP].ack
                    latest_tcp_info2['ack'] = pkt[TCP].seq + len(pkt[TCP].payload)
                    latest_tcp_info2['ttl'] = pkt[IP].ttl
                    latest_tcp_info2['ip_options'] = pkt[IP].options
                    latest_tcp_info2['tcp_window'] = pkt[TCP].window if hasattr(pkt[TCP], 'window') else window_size
                    latest_tcp_info2['tcp_options'] = pkt[TCP].options

                # ACKパケットを作成して送信
                # TS val/ecrの計算
                tsval = None
                tsecr = None
                if local_port == local_port1 and remote_port == remote_port1:
                    # global primary_ack_ts
                    if primary_ack_ts['tsval'] is not None and primary_ack_ts['timestamp'] is not None:
                        tsval = int(time.time() * 1000 - primary_ack_ts['timestamp'] * 1000 + primary_ack_ts['tsval'])
                    # pktのTCPオプションからtsval抽出
                    if hasattr(pkt[TCP], 'options'):
                        for opt in pkt[TCP].options:
                            if isinstance(opt, tuple) and opt[0] == 'Timestamp':
                                tsecr = opt[1][0]
                                break
                elif local_port == local_port2 and remote_port == remote_port2:
                    # global secondary_ack_ts
                    if secondary_ack_ts['tsval'] is not None and secondary_ack_ts['timestamp'] is not None:
                        tsval = int(time.time() * 1000 - secondary_ack_ts['timestamp'] * 1000 + secondary_ack_ts['tsval'])
                    if hasattr(pkt[TCP], 'options'):
                        for opt in pkt[TCP].options:
                            if isinstance(opt, tuple) and opt[0] == 'Timestamp':
                                tsecr = opt[1][0]
                                break
                # TCPオプションを[nop,nop,Timestamp]で明示的に構築
                tcp_options = []
                if tsval is not None and tsecr is not None:
                    tcp_options = [('NOP', None), ('NOP', None), ('Timestamp', (tsval, tsecr))]
                elif tsval is not None and tsecr is None:
                    tcp_options = [('NOP', None), ('NOP', None), ('Timestamp', (tsval, tsecr))] # tsecrがNoneのときも送ってみる
                else:
                    # tcp_options = pkt[TCP].options
                    tcp_options = []
                ack_packet = IP(
                    src=pkt[IP].dst,
                    dst=pkt[IP].src,
                    id=RandShort(),
                    ttl=ttl,
                    options=pkt[IP].options
                )/TCP(
                    sport=local_port,
                    dport=remote_port,
                    seq=pkt[TCP].ack,
                    ack=pkt[TCP].seq + len(pkt[TCP].payload),
                    flags='A',
                    window=window_size,
                    options=tcp_options
                )

                global last_help_mtime, help_packet_pending, help_packet_seq, help_packet_ack, help_ack_count


                # help.txtトリガーACK判定: 0400e228に対するACKが来たか
                if help_packet_pending and local_port == local_port1 and remote_port == remote_port1:
                    expected_ack = (help_packet_seq or 0) + 4
                    if pkt[TCP].ack == expected_ack:
                        print(f"[help.txt] ACK RECV! {time.strftime('%Y-%m-%d %H:%M:%S')}")
                        help_packet_pending = False
                        help_packet_seq = None
                        help_packet_ack = None
                        help_ack_count = 0

                

                # help.txtトリガー: 0400e228送信 & pending管理
                if os.path.exists("./help.txt") and local_port == local_port1:
                    mtime = os.path.getmtime("./help.txt")
                    if (last_help_mtime is None or mtime > last_help_mtime):
                        # まだACKが返ってきていない場合は再送
                        tcp_layer = ack_packet.getlayer(TCP)
                        tcp_layer.flags = 'PA'
                        ack_packet = ack_packet / Raw(load=bytes.fromhex("0400e228"))
                        print(f"HELP!(PA) {time.strftime('%Y-%m-%d %H:%M:%S')}")
                        # 送信したseq/ackを記録
                        help_packet_seq = tcp_layer.seq
                        help_packet_ack = tcp_layer.ack
                        help_packet_pending = True
                        last_help_mtime = mtime
                        help_ack_count = 0
                        # os.remove("help.txt")
                        # last_help_mtime = None




                # ACKカウントをインクリメント
                global ack_count1, ack_count2


                if local_port == local_port1 and remote_port == remote_port1:
                    ack_count1 += 1
                    # help_packet_pending中は通常ACKカウント
                    # if help_packet_pending:
                    #     help_ack_count += 1
                    #     if help_ack_count >= help_ack_count_threshold:
                    #         # help_ack_count_threshold回目で再送
                    #         tcp_layer = ack_packet.getlayer(TCP)
                    #         tcp_layer.flags = 'PA'
                    #         ack_packet = ack_packet / Raw(load=bytes.fromhex("0400e228"))
                    #         print("[help.txt] 0400e228 RETRANSMIT (help_ack_count_threshold normal ACKs)")
                    #         help_packet_seq = tcp_layer.seq
                    #         help_packet_ack = tcp_layer.ack
                    #         help_ack_count = 0
                    #         # 送信
                    #         ack_packet = Ether(dst=remote_mac, src=local_mac)/ack_packet
                    #         sendp(ack_packet, iface="enp1s0", verbose=0)
                    #         return
                elif local_port == local_port2 and remote_port == remote_port2:
                    # RSTフラグが立っていない場合のみカウント
                    if not (pkt[TCP].flags & 0x04):
                        ack_count2 += 1

                print(f"✅ ACK sent | TSval={tsval}, TSecr={tsecr}")
                ack_packet = Ether(dst=remote_mac, src=local_mac)/ack_packet

                # tcp_optionsが空でないときのみ送信
                if tcp_options:
                    sendp(ack_packet, iface="enp1s0", verbose=0)

                return

                # 最初のPSH-ACKを即時送信（1回だけ、ポートごとに分岐）
                if sport == src_port1 and dport == dst_port1 and not latest_tcp_info1.get('psh_sent'):
                    psh_packet = IP(
                        src=latest_tcp_info1['src_ip'],
                        dst=latest_tcp_info1['dst_ip'],
                        id=RandShort(),
                        ttl=pkt[IP].ttl,
                        options=pkt[IP].options
                    )/TCP(
                        sport=latest_tcp_info1['sport'],
                        dport=latest_tcp_info1['dport'],
                        seq=latest_tcp_info1['seq'],
                        ack=latest_tcp_info1['ack'],
                        flags='PA',
                        window=window_size,
                        options=tcp_options
                    )/Raw(load=bytes.fromhex("04001627"))
                    # send(psh_packet, iface="enp1s0", verbose=0)
                    psh_packet = Ether(dst=dst_mac)/psh_packet
                    sendp(psh_packet, iface="enp1s0", verbose=0)
                    print(f"[+] First PSH-ACK sent to {latest_tcp_info1['dst_ip']}:{latest_tcp_info1['dport']}")
                    latest_tcp_info1['psh_sent'] = True
                elif sport == src_port2 and dport == dst_port2 and not latest_tcp_info2.get('psh_sent'):
                    psh_packet = IP(
                        src=latest_tcp_info2['src_ip'],
                        dst=latest_tcp_info2['dst_ip'],
                        id=RandShort(),
                        ttl=pkt[IP].ttl,
                        options=pkt[IP].options
                    )/TCP(
                        sport=latest_tcp_info2['sport'],
                        dport=latest_tcp_info2['dport'],
                        seq=latest_tcp_info2['seq'],
                        ack=latest_tcp_info2['ack'],
                        flags='PA',
                        window=window_size,
                        options=tcp_options
                    )/Raw(load=bytes.fromhex("040058c3"))
                    # send(psh_packet, iface="enp1s0", verbose=0)
                    psh_packet = Ether(dst=dst_mac)/psh_packet
                    sendp(psh_packet, iface="enp1s0", verbose=0)
                    print(f"[+] First PSH-ACK sent to {latest_tcp_info2['dst_ip']}:{latest_tcp_info2['dport']}")
                    latest_tcp_info2['psh_sent'] = True

# タイムスロットでPSH-ACKを送信
def periodic_psh_sender1():
    # sniffでACK送信が行われるまで待機（両方）
    # while (latest_tcp_info1['src_ip'] is None or not latest_tcp_info1.get('psh_sent')):
    while not latest_tcp_info1.get('psh_sent'):
        time.sleep(0.1)
    global ack_count1
    while True:
        if latest_tcp_info1['psh_sent']:
            if ack_count1 >= 1:
                time.sleep(15)
                with latest_tcp_info_lock:
                    # TCP options (NOP,NOP,Timestamp) 計算
                    tsval = None
                    tsecr = None
                    if primary_ack_ts['tsval'] is not None and primary_ack_ts['timestamp'] is not None:
                        tsval = int(time.time() * 1000 - primary_ack_ts['timestamp'] * 1000 + primary_ack_ts['tsval'])
                    tcp_opts = latest_tcp_info1.get('tcp_options', [])
                    if tcp_opts:
                        for opt in tcp_opts:
                            if isinstance(opt, tuple) and opt[0] == 'Timestamp':
                                tsecr = opt[1][0]
                                break
                    tcp_options = []
                    if tsval is not None and tsecr is not None:
                        tcp_options = [('NOP', None), ('NOP', None), ('Timestamp', (tsval, tsecr))]
                    else:
                        tcp_options = tcp_opts
                    psh_packet = IP(
                        src=latest_tcp_info1['src_ip'],
                        dst=latest_tcp_info1['dst_ip'],
                        id=RandShort(),
                        ttl=latest_tcp_info1.get('ttl', 64),
                        options=latest_tcp_info1.get('ip_options', [])
                    )/TCP(
                        sport=latest_tcp_info1['sport'],
                        dport=latest_tcp_info1['dport'],
                        seq=latest_tcp_info1['seq'],
                        ack=latest_tcp_info1['ack'],
                        flags='PA',
                        window=latest_tcp_info1.get('tcp_window', window_size),
                        options=tcp_options
                    )/Raw(load=bytes.fromhex("04001627"))
                    psh_packet = Ether(dst=remote_mac, src=local_mac)/psh_packet
                    sendp(psh_packet, iface="enp1s0", verbose=0)
                    print(f"[+] Periodic PSH-ACK sent to {latest_tcp_info1['dst_ip']}:{latest_tcp_info1['dport']} | TSval={tsval}, TSecr={tsecr}")
                    ack_count1 = 0
            else:
                time.sleep(1)

def periodic_psh_sender2():
    # sniffでACK送信が行われるまで待機（両方）
    # while (latest_tcp_info2['src_ip'] is None or not latest_tcp_info2.get('psh_sent')):
    while not latest_tcp_info2.get('psh_sent'):
        time.sleep(0.1)
    global ack_count2
    while True:
        if latest_tcp_info2['psh_sent']:
            # 2側で何か失敗したときは送る（periodicにackが返ってこなかった）
            if ack_count2 >= 1 or ack_count1 >= 1:
                time.sleep(15)
                with latest_tcp_info_lock:
                    # TCP options (NOP,NOP,Timestamp) 計算
                    tsval = None
                    tsecr = None
                    if secondary_ack_ts['tsval'] is not None and secondary_ack_ts['timestamp'] is not None:
                        tsval = int(time.time() * 1000 - secondary_ack_ts['timestamp'] * 1000 + secondary_ack_ts['tsval'])
                    tcp_opts = latest_tcp_info2.get('tcp_options', [])
                    if tcp_opts:
                        for opt in tcp_opts:
                            if isinstance(opt, tuple) and opt[0] == 'Timestamp':
                                tsecr = opt[1][0]
                                break
                    tcp_options = []
                    if tsval is not None and tsecr is not None:
                        tcp_options = [('NOP', None), ('NOP', None), ('Timestamp', (tsval, tsecr))]
                    else:
                        tcp_options = tcp_opts
                    psh_packet = IP(
                        src=latest_tcp_info2['src_ip'],
                        dst=latest_tcp_info2['dst_ip'],
                        id=RandShort(),
                        ttl=latest_tcp_info2.get('ttl', 64),
                        options=latest_tcp_info2.get('ip_options', [])
                    )/TCP(
                        sport=latest_tcp_info2['sport'],
                        dport=latest_tcp_info2['dport'],
                        seq=latest_tcp_info2['seq'],
                        ack=latest_tcp_info2['ack'],
                        flags='PA',
                        window=latest_tcp_info2.get('tcp_window', window_size),
                        options=tcp_options
                    )/Raw(load=bytes.fromhex("040058c3"))
                    psh_packet = Ether(dst=remote_mac, src=local_mac)/psh_packet
                    sendp(psh_packet, iface="enp1s0", verbose=0)
                    print(f"[+] Periodic PSH-ACK sent to {latest_tcp_info2['dst_ip']}:{latest_tcp_info2['dport']} | TSval={tsval}, TSecr={tsecr}")
                    ack_count2 = 0
            else:
                time.sleep(1)



def make_ack_filter(local_port, remote_port):
    def ack_filter(pkt):
        # TCP flags: 0x10 is ACK only, but we want any packet with ACK flag set
        # ACK,PSH(0x18)フラグのみ対象（ACKのみはスキップ）
        # print(f"DEBUG{ports}: Packet from {pkt[IP].src}:{pkt[TCP].sport} to {pkt[IP].dst}:{pkt[TCP].dport}, flags={pkt[TCP].flags}, seq={pkt[TCP].seq}, ack={pkt[TCP].ack}")
        if TCP in pkt and pkt[TCP].flags == 0x18 and pkt[TCP].sport == local_port and pkt[TCP].dport == remote_port:
            tsval = None
            tsecr = None
            # TCPオプションからTimestamp抽出
            if hasattr(pkt[TCP], 'options'):
                for opt in pkt[TCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'Timestamp':
                        tsval = opt[1][0]
                        tsecr = opt[1][1]
                        break
            now = time.time()
            if pkt[TCP].dport in primary_ports:
                # global primary_ack_ts
                # global local_port1, remote_port1
                # local_port1 = pkt[TCP].sport
                # remote_port1 = pkt[TCP].dport
                primary_ack_ts['tsval'] = tsval
                primary_ack_ts['tsecr'] = tsecr
                primary_ack_ts['timestamp'] = now
                latest_tcp_info1['psh_sent'] = True
            elif pkt[TCP].dport in secondary_ports:
                # global secondary_ack_ts
                # global local_port2, remote_port2
                # local_port2 = pkt[TCP].sport
                # remote_port2 = pkt[TCP].dport
                secondary_ack_ts['tsval'] = tsval
                secondary_ack_ts['tsecr'] = tsecr
                secondary_ack_ts['timestamp'] = now
                latest_tcp_info2['psh_sent'] = True


            print(f"✅ Packet matching ACK filter: {pkt.summary()} | TSval={tsval}, TSecr={tsecr}, time={now}")
            print(now * 1000 - tsval)
            return True
        else:
            return False
    return ack_filter  # ← これが必要

def debug_packet_callback(pkt):
    return
    if IP in pkt and TCP in pkt:
        print(f"DEBUG: Packet from {pkt[IP].src}:{pkt[TCP].sport} to {pkt[IP].dst}:{pkt[TCP].dport}, flags={pkt[TCP].flags}, seq={pkt[TCP].seq}, ack={pkt[TCP].ack}")

# local_port1 = 0
# remote_port1 = 0 # 11531
# local_port2 = 0
# remote_port2 = 0 # 11538


# バックグラウンドでタイムスロット送信を開始
threading.Thread(target=periodic_psh_sender1, daemon=True).start()
threading.Thread(target=periodic_psh_sender2, daemon=True).start()

sniff(iface="enp1s0", filter=f"tcp and ip dst {remote_ip}", prn=debug_packet_callback, stop_filter=make_ack_filter(local_port1, remote_port1), store=0)
sniff(iface="enp1s0", filter=f"tcp and ip dst {remote_ip}", prn=debug_packet_callback, stop_filter=make_ack_filter(local_port2, remote_port2), store=0)
        
# sys.exit(0)

# 初期設定
setup_iptables()
atexit.register(cleanup_iptables)


print(f"🔍 Capturing packets from {remote_ip} on enp1s0... (Press Ctrl+C to stop)")
# パケットをキャプチャ (パケットは自動的に破棄される)
sniff(iface="enp1s0", filter=f"tcp and ip src {remote_ip}", prn=packet_callback, store=0)
