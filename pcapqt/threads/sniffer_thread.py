from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw, conf
import traceback
import socket


class SnifferThread(QThread):
    # Emit bytes (thread-safe) instead of packet object
    packet_captured = pyqtSignal(bytes, dict)
    # Signal for capture errors
    capture_error = pyqtSignal(str)

    def __init__(self, iface=None):
        super().__init__()
        self.is_running = False
        self.packet_count = 0
        self.start_time = None
        self.iface = iface  # Network interface to capture from
        self._sniff_timeout = 1  # Timeout in seconds for each sniff cycle

    def set_interface(self, iface):
        """Set the network interface to capture from."""
        self.iface = iface

    def run(self):
        self.is_running = True
        self.start_time = datetime.now()
        self.packet_count = 0

        def packet_handler(packet):
            # Don't process if stopped
            if not self.is_running:
                return  # Return None instead of True to avoid printing

            try:
                self.packet_count += 1
                packet_info = self.parse_packet(packet)
                # Convert packet to bytes for thread-safe transfer
                # This creates a copy that is safe to pass between threads
                packet_bytes = bytes(packet)
                self.packet_captured.emit(packet_bytes, packet_info)
            except Exception as e:
                print(f"Packet handler error: {e}")
                traceback.print_exc()

        try:
            # Use timeout-based sniffing loop to avoid blocking on inactive interfaces
            # This allows the thread to check is_running periodically and stop gracefully
            while self.is_running:
                try:
                    # Sniff with timeout - returns after timeout even if no packets
                    sniff(
                        prn=packet_handler, 
                        store=False, 
                        stop_filter=lambda x: not self.is_running, 
                        iface=self.iface,
                        timeout=self._sniff_timeout  # Key: timeout prevents blocking
                    )
                except socket.timeout:
                    # Normal timeout, just continue the loop
                    pass
                except Exception as e:
                    # Check if we should stop
                    if not self.is_running:
                        break
                    # Log but continue trying
                    print(f"Sniff cycle error: {e}")
                    
        except PermissionError as e:
            error_msg = f"Permission error: {e}. Please run as Administrator."
            print(error_msg)
            self.capture_error.emit(error_msg)
        except OSError as e:
            error_msg = f"OS error during sniffing: {e}. Check if Npcap is installed."
            print(error_msg)
            self.capture_error.emit(error_msg)
        except Exception as e:
            error_msg = f"Sniffing error: {e}"
            print(error_msg)
            traceback.print_exc()
            self.capture_error.emit(error_msg)

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
