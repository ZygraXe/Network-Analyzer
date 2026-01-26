import sys
sys.path.append("/home/kali/dpkt-master")
import socket
import dpkt
import time

def packet_sniff(interface="eth0"):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    try:
        sock.bind((interface, 0)) 

        while True:
            raw_data, addr = sock.recvfrom(65535)
            timestamp = time.time()
            process_packet(raw_data, timestamp)

    except KeyboardInterrupt:
        print("\n[+] Stopping sniffing...")

    except Exception as e:
        print("Error in sniffer:", e)

    finally:
        print("[+] Closing socket safely...")
        sock.close()
        print("[+] Socket closed. Interface restored.")


def process_packet(raw_data, timestamp):
    try:
        eth = dpkt.ethernet.Ethernet(raw_data)

        src_addr = mac_addr(eth.src)
        dest_addr = mac_addr(eth.dst)  

        eth_type = eth.type
        print("\n================ NEW PACKET ================")
        print(f"Timestamp          : {timestamp}")
        print(f"Source Mac         : {src_addr}")
        print(f"Destination Mac    : {dest_addr}")
        print(f"EtherType          : {hex(eth_type)}")

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            print(f"Source IP           : {src_ip}")
            print(f"Destination IP      : {dst_ip}")
            print(f"Protocol            : {ip.p}")

            if ip.p == dpkt.ip.IP_PROTO_TCP:   
                handle_tcp_packet(ip)

            elif ip.p == dpkt.ip.IP_PROTO_UDP: 
                handle_udp_packet(ip)

            else:
                print("Other IP protocol detected")

        else:
            print("Non-IP packet detected")

    except Exception as e:
        print("There is problem with parsing the packet: ", e)


def handle_tcp_packet(ip):
    tcp = ip.data
    print("----- TCP Packet -----")
    print(f"Source Port        : {tcp.sport}")
    print(f"Destination Port   : {tcp.dport}")
    print(f"Sequence Num       : {tcp.seq}")
    print(f"Ack Num            : {tcp.ack}")
    print(f"Flags              : {tcp.flags}")


def handle_udp_packet(ip):
    udp = ip.data
    print("----- UDP Packet -----")
    print(f"Source Port        : {udp.sport}")
    print(f"Destination Port   : {udp.dport}")
    print(f"Length             : {udp.ulen}")


def mac_addr(raw_bytes):
    return ":".join(f"{b:02x}" for b in raw_bytes)


if __name__ == "__main__":
    packet_sniff("eth0")
