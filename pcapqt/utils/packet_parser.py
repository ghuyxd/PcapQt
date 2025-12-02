from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw
from datetime import datetime


class PacketParser:
    @staticmethod
    def parse_packet(packet, packet_count, start_time):

        info = {
            'no': packet_count,
            'time': (datetime.now() - start_time).total_seconds(),
            'src': 'Unknown',
            'dst': 'Unknown',
            'protocol': 'Unknown',
            'length': len(packet),
            'info': ''
        }

        if Ether in packet:
            info['src'] = packet[Ether].src
            info['dst'] = packet[Ether].dst

        if IP in packet:
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            info['protocol'] = packet[IP].proto

            if TCP in packet:
                info['protocol'] = 'TCP'
                info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport} [Flags: {packet[TCP].flags}]"
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['info'] = f"{packet[UDP].sport} → {packet[UDP].dport}"
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['info'] = f"Type: {packet[ICMP].type}"

        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src'] = packet[ARP].psrc
            info['dst'] = packet[ARP].pdst
            info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"

        return info

    @staticmethod
    def get_protocol_name(proto_num):
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protocols.get(proto_num, 'Unknown')

    @staticmethod
    def get_icmp_type(icmp_type):
        types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        return types.get(icmp_type, 'Unknown')

    @staticmethod
    def get_arp_op(op):
        ops = {1: 'Request', 2: 'Reply'}
        return ops.get(op, 'Unknown')

    @staticmethod
    def parse_tcp_flags(flags):
        flag_list = []
        if flags & 0x01: flag_list.append('FIN')
        if flags & 0x02: flag_list.append('SYN')
        if flags & 0x04: flag_list.append('RST')
        if flags & 0x08: flag_list.append('PSH')
        if flags & 0x10: flag_list.append('ACK')
        if flags & 0x20: flag_list.append('URG')
        return ', '.join(flag_list) if flag_list else 'None'

    @staticmethod
    def get_packet_details(packet, packet_index):
        details = []

        details.append(['=== Frame ===', ''])
        details.append(['Frame Number', packet_index + 1])
        details.append(['Frame Length', f"{len(packet)} bytes"])
        details.append(['Capture Length', f"{len(packet)} bytes"])

        if Ether in packet:
            details.append(['=== Ethernet II ===', ''])
            details.append(['Destination MAC', packet[Ether].dst])
            details.append(['Source MAC', packet[Ether].src])
            details.append(['Type', f"{hex(packet[Ether].type)} ({packet[Ether].type})"])

        if IP in packet:
            details.append(['=== Internet Protocol ===', ''])
            details.append(['Version', packet[IP].version])
            details.append(['Header Length', f"{packet[IP].ihl * 4} bytes"])
            details.append(['Type of Service', f"0x{packet[IP].tos:02x}"])
            details.append(['Total Length', f"{packet[IP].len} bytes"])
            details.append(['Identification', f"0x{packet[IP].id:04x} ({packet[IP].id})"])
            details.append(['Flags', str(packet[IP].flags)])
            details.append(['Fragment Offset', packet[IP].frag])
            details.append(['Time to Live', packet[IP].ttl])
            details.append(['Protocol', f"{packet[IP].proto} ({PacketParser.get_protocol_name(packet[IP].proto)})"])
            details.append(['Header Checksum', f"0x{packet[IP].chksum:04x}"])
            details.append(['Source IP', packet[IP].src])
            details.append(['Destination IP', packet[IP].dst])

        if TCP in packet:
            details.append(['=== Transmission Control Protocol ===', ''])
            details.append(['Source Port', packet[TCP].sport])
            details.append(['Destination Port', packet[TCP].dport])
            details.append(['Sequence Number', packet[TCP].seq])
            details.append(['Acknowledgment Number', packet[TCP].ack])
            details.append(['Header Length', f"{packet[TCP].dataofs * 4} bytes"])
            details.append(['Flags', PacketParser.parse_tcp_flags(packet[TCP].flags)])
            details.append(['Window Size', packet[TCP].window])
            details.append(['Checksum', f"0x{packet[TCP].chksum:04x}"])
            details.append(['Urgent Pointer', packet[TCP].urgptr])

            if packet[TCP].options:
                details.append(['Options', str(packet[TCP].options)])

        elif UDP in packet:
            details.append(['=== User Datagram Protocol ===', ''])
            details.append(['Source Port', packet[UDP].sport])
            details.append(['Destination Port', packet[UDP].dport])
            details.append(['Length', f"{packet[UDP].len} bytes"])
            details.append(['Checksum', f"0x{packet[UDP].chksum:04x}"])

        elif ICMP in packet:
            details.append(['=== Internet Control Message Protocol ===', ''])
            details.append(['Type', f"{packet[ICMP].type} ({PacketParser.get_icmp_type(packet[ICMP].type)})"])
            details.append(['Code', packet[ICMP].code])
            details.append(['Checksum', f"0x{packet[ICMP].chksum:04x}"])

            if hasattr(packet[ICMP], 'id'):
                details.append(['Identifier', packet[ICMP].id])
            if hasattr(packet[ICMP], 'seq'):
                details.append(['Sequence Number', packet[ICMP].seq])

        if ARP in packet:
            details.append(['=== Address Resolution Protocol ===', ''])
            details.append(['Hardware Type', f"{packet[ARP].hwtype} (Ethernet)"])
            details.append(['Protocol Type', f"0x{packet[ARP].ptype:04x} (IPv4)"])
            details.append(['Hardware Size', packet[ARP].hwlen])
            details.append(['Protocol Size', packet[ARP].plen])
            details.append(['Operation', f"{packet[ARP].op} ({PacketParser.get_arp_op(packet[ARP].op)})"])
            details.append(['Sender MAC', packet[ARP].hwsrc])
            details.append(['Sender IP', packet[ARP].psrc])
            details.append(['Target MAC', packet[ARP].hwdst])
            details.append(['Target IP', packet[ARP].pdst])

        if Raw in packet:
            details.append(['=== Data ===', ''])
            raw_data = bytes(packet[Raw].load)
            details.append(['Data Length', f"{len(raw_data)} bytes"])

            preview_len = min(128, len(raw_data))
            hex_preview = ' '.join(f"{b:02x}" for b in raw_data[:preview_len])
            if len(raw_data) > preview_len:
                hex_preview += '...'
            details.append(['Data (hex)', hex_preview])

            ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_data[:preview_len])
            if len(raw_data) > preview_len:
                ascii_preview += '...'
            details.append(['Data (ASCII)', ascii_preview])

        return details