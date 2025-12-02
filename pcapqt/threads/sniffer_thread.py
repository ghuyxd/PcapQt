from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw


class SnifferThread(QThread):
    packet_captured = pyqtSignal(object, dict)

    def __init__(self):
        super().__init__()
        self.is_running = False
        self.packet_count = 0
        self.start_time = None

    def run(self):
        self.is_running = True
        self.start_time = datetime.now()
        self.packet_count = 0

        def packet_handler(packet):
            if not self.is_running:
                return True

            self.packet_count += 1
            packet_info = self.parse_packet(packet)
            self.packet_captured.emit(packet, packet_info)

        try:
            sniff(prn=packet_handler, store=False, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            print(f"Sniffing error: {e}")

    def parse_packet(self, packet):
        info = {
            'no': self.packet_count,
            'time': (datetime.now() - self.start_time).total_seconds(),
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

    def stop(self):
        self.is_running = False
