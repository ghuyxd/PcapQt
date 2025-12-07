# -*- coding: utf-8 -*-
"""
Packet parser supporting OSI Layers 1-7.

Layer 1 (Physical): Frame information
Layer 2 (Data Link): Ethernet
Layer 3 (Network): IP, ARP
Layer 4 (Transport): TCP, UDP, ICMP
Layer 5 (Session): Connection management, session control
Layer 6 (Presentation): Data encoding, encryption, compression
Layer 7 (Application): Protocol-specific data
"""

from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw, DNS
from datetime import datetime
import struct
import binascii

from .protocol_parsers import (
    WELL_KNOWN_PORTS,
    ETHER_TYPES,
    TLS_VERSIONS,
    TLS_CONTENT_TYPES,
    parse_dns_app,
    parse_http_app,
    parse_tls_app,
    parse_dhcp_app,
    parse_ftp_app,
    parse_smtp_app,
    parse_ssh_app,
    parse_pop3_app,
    parse_imap_app,
    parse_ntp_app,
    parse_snmp_app,
    parse_telnet_app,
    parse_raw_data,
)


class PacketParser:
    """Packet parser supporting OSI Layers 1-7."""
    
    @staticmethod
    def parse_packet(packet, packet_count, start_time):
        """Parse a packet and return basic info for table display."""
        info = {
            'no': packet_count,
            'time': (datetime.now() - start_time).total_seconds(),
            'src': 'Unknown', 'dst': 'Unknown',
            'protocol': 'Unknown', 'length': len(packet), 'info': ''
        }

        if Ether in packet:
            info['src'] = packet[Ether].src
            info['dst'] = packet[Ether].dst

        if IP in packet:
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            info['protocol'] = packet[IP].proto

            if TCP in packet:
                sport, dport = packet[TCP].sport, packet[TCP].dport
                app_proto = PacketParser._detect_app_protocol(packet, sport, dport)
                info['protocol'] = app_proto if app_proto else 'TCP'
                info['info'] = f"{sport} → {dport} [Flags: {packet[TCP].flags}]"
            elif UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
                app_proto = PacketParser._detect_app_protocol(packet, sport, dport)
                info['protocol'] = app_proto if app_proto else 'UDP'
                info['info'] = f"{sport} → {dport}"
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['info'] = f"Type: {packet[ICMP].type}"
        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src'] = packet[ARP].psrc
            info['dst'] = packet[ARP].pdst
            op = packet[ARP].op
            if op == 1:
                info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            else:
                info['info'] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
        elif Ether in packet:
            # Non-IP Ethernet frame
            ether_type = packet[Ether].type
            proto_name = ETHER_TYPES.get(ether_type, f'Ethernet (0x{ether_type:04x})')
            info['protocol'] = proto_name
            info['info'] = f"EtherType: 0x{ether_type:04x}"

        return info

    @staticmethod
    def _detect_app_protocol(packet, sport, dport):
        """Detect application layer protocol based on ports and payload."""
        if sport == 53 or dport == 53:
            return 'DNS'
        if sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
            if Raw in packet and PacketParser._is_http(bytes(packet[Raw].load)):
                return 'HTTP'
        if sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
            return 'TLS'
        if sport in (67, 68) or dport in (67, 68):
            return 'DHCP'
        if sport == 21 or dport == 21:
            return 'FTP'
        if sport == 20 or dport == 20:
            return 'FTP-Data'
        if sport == 25 or dport == 25 or sport == 587 or dport == 587 or sport == 465 or dport == 465:
            return 'SMTP'
        if sport == 22 or dport == 22:
            return 'SSH'
        if sport == 110 or dport == 110 or sport == 995 or dport == 995:
            return 'POP3'
        if sport == 143 or dport == 143 or sport == 993 or dport == 993:
            return 'IMAP'
        if sport == 123 or dport == 123:
            return 'NTP'
        if sport == 161 or dport == 161 or sport == 162 or dport == 162:
            return 'SNMP'
        if sport == 23 or dport == 23:
            return 'Telnet'
        return None

    @staticmethod
    def _is_http(payload):
        """Check if payload looks like HTTP."""
        if not payload:
            return False
        try:
            text = payload[:20].decode('utf-8', errors='ignore').upper()
            return any(text.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'HTTP/'])
        except:
            return False

    @staticmethod
    def get_protocol_name(proto_num):
        """Get protocol name from IP protocol number."""
        return {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto_num, 'Unknown')

    @staticmethod
    def get_icmp_type(icmp_type):
        """Get ICMP type name."""
        return {0: 'Echo Reply', 3: 'Destination Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}.get(icmp_type, 'Unknown')

    @staticmethod
    def get_arp_op(op):
        """Get ARP operation name."""
        return {1: 'Request', 2: 'Reply'}.get(op, 'Unknown')

    @staticmethod
    def parse_tcp_flags(flags):
        """Parse TCP flags to human-readable format."""
        flag_list = []
        if flags & 0x01:
            flag_list.append('FIN')
        if flags & 0x02:
            flag_list.append('SYN')
        if flags & 0x04:
            flag_list.append('RST')
        if flags & 0x08:
            flag_list.append('PSH')
        if flags & 0x10:
            flag_list.append('ACK')
        if flags & 0x20:
            flag_list.append('URG')
        return ', '.join(flag_list) if flag_list else 'None'

    @staticmethod
    def get_packet_details(packet, packet_index):
        """Get detailed packet information for all OSI layers."""
        details = []
        
        # === Layer 1: Physical ===
        details.append(['=== Layer 1: Physical (Frame) ===', ''])
        details.append(['Frame Number', packet_index + 1])
        details.append(['Frame Length', f"{len(packet)} bytes"])
        details.append(['Capture Length', f"{len(packet)} bytes"])

        # === Layer 2: Data Link ===
        if Ether in packet:
            details.append(['=== Layer 2: Data Link (Ethernet II) ===', ''])
            details.append(['Destination MAC', packet[Ether].dst])
            details.append(['Source MAC', packet[Ether].src])
            ether_type = packet[Ether].type
            ETHER_TYPE_NAMES = {
                0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6',
                0x8100: 'VLAN (802.1Q)', 0x88CC: 'LLDP', 0x8892: 'PROFINET'
            }
            type_name = ETHER_TYPE_NAMES.get(ether_type, '')
            if type_name:
                details.append(['EtherType', f"0x{ether_type:04x} ({type_name})"])
            else:
                details.append(['EtherType', f"0x{ether_type:04x}"])
            
            # Calculate Frame Check Sequence (FCS) - CRC32
            raw_bytes = bytes(packet)
            if len(raw_bytes) >= 14:
                fcs = binascii.crc32(raw_bytes) & 0xffffffff
                details.append(['Frame Check Sequence (FCS)', f"0x{fcs:08x}"])

        # === Layer 3: Network ===
        if IP in packet:
            details.append(['=== Layer 3: Network (IPv4) ===', ''])
            details.append(['Version', packet[IP].version])
            details.append(['Header Length', f"{packet[IP].ihl * 4} bytes"])
            details.append(['TOS/DSCP', f"0x{packet[IP].tos:02x}"])
            details.append(['Total Length', f"{packet[IP].len} bytes"])
            details.append(['Identification', f"0x{packet[IP].id:04x}"])
            details.append(['Flags', str(packet[IP].flags)])
            details.append(['Fragment Offset', packet[IP].frag])
            details.append(['TTL', packet[IP].ttl])
            details.append(['Protocol', f"{packet[IP].proto} ({PacketParser.get_protocol_name(packet[IP].proto)})"])
            details.append(['Checksum', f"0x{packet[IP].chksum:04x}"])
            details.append(['Source IP', packet[IP].src])
            details.append(['Destination IP', packet[IP].dst])

        if ARP in packet:
            details.append(['=== Layer 3: Network (ARP) ===', ''])
            details.append(['Hardware Type', f"{packet[ARP].hwtype} (Ethernet)"])
            details.append(['Protocol Type', f"0x{packet[ARP].ptype:04x} (IPv4)"])
            details.append(['Operation', f"{packet[ARP].op} ({PacketParser.get_arp_op(packet[ARP].op)})"])
            details.append(['Sender MAC', packet[ARP].hwsrc])
            details.append(['Sender IP', packet[ARP].psrc])
            details.append(['Target MAC', packet[ARP].hwdst])
            details.append(['Target IP', packet[ARP].pdst])

        # === Layer 4: Transport ===
        sport = dport = 0
        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
            details.append(['=== Layer 4: Transport (TCP) ===', ''])
            details.append(['Source Port', sport])
            details.append(['Destination Port', dport])
            details.append(['Sequence Number', packet[TCP].seq])
            details.append(['Acknowledgment', packet[TCP].ack])
            details.append(['Header Length', f"{packet[TCP].dataofs * 4} bytes"])
            details.append(['Flags', PacketParser.parse_tcp_flags(packet[TCP].flags)])
            details.append(['Window Size', packet[TCP].window])
            details.append(['Checksum', f"0x{packet[TCP].chksum:04x}"])
            details.append(['Urgent Pointer', packet[TCP].urgptr])
            if packet[TCP].options:
                details.append(['Options', str(packet[TCP].options)])
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
            details.append(['=== Layer 4: Transport (UDP) ===', ''])
            details.append(['Source Port', sport])
            details.append(['Destination Port', dport])
            details.append(['Length', f"{packet[UDP].len} bytes"])
            details.append(['Checksum', f"0x{packet[UDP].chksum:04x}"])
        elif ICMP in packet:
            details.append(['=== Layer 4: Transport (ICMP) ===', ''])
            details.append(['Type', f"{packet[ICMP].type} ({PacketParser.get_icmp_type(packet[ICMP].type)})"])
            details.append(['Code', packet[ICMP].code])
            details.append(['Checksum', f"0x{packet[ICMP].chksum:04x}"])
            if hasattr(packet[ICMP], 'id'):
                details.append(['Identifier', packet[ICMP].id])
            if hasattr(packet[ICMP], 'seq'):
                details.append(['Sequence', packet[ICMP].seq])

        # === Layer 5: Session ===
        details.append(['=== Layer 5: Session ===', ''])
        if TCP in packet:
            flags = packet[TCP].flags
            details.append(['Session Type', 'TCP (Connection-Oriented)'])
            if flags & 0x02 and not (flags & 0x10):
                details.append(['Session State', 'SYN_SENT - Initiating connection'])
                details.append(['Dialog Control', 'Half-Open (Awaiting SYN-ACK)'])
            elif flags & 0x02 and flags & 0x10:
                details.append(['Session State', 'SYN_RECEIVED - Responding'])
                details.append(['Dialog Control', 'Half-Open (Sent SYN-ACK)'])
            elif flags & 0x01:
                details.append(['Session State', 'FIN_WAIT - Terminating'])
                details.append(['Dialog Control', 'Closing session'])
            elif flags & 0x04:
                details.append(['Session State', 'RESET - Connection aborted'])
                details.append(['Dialog Control', 'Session terminated abnormally'])
            else:
                details.append(['Session State', 'ESTABLISHED - Active'])
                details.append(['Dialog Control', 'Full-Duplex communication'])
            details.append(['Synchronization', f"SEQ={packet[TCP].seq}, ACK={packet[TCP].ack}"])
        elif UDP in packet:
            details.append(['Session Type', 'UDP (Connectionless)'])
            details.append(['Session State', 'Stateless - No session management'])
            details.append(['Dialog Control', 'Simplex/Datagram mode'])
            details.append(['Synchronization', 'N/A (Unreliable delivery)'])
        else:
            details.append(['Session Type', 'N/A'])
            details.append(['Session State', 'No transport layer detected'])

        # === Layer 6: Presentation ===
        details.append(['=== Layer 6: Presentation ===', ''])
        
        is_encrypted = sport in (443, 8443, 22, 993, 995, 465) or dport in (443, 8443, 22, 993, 995, 465)
        
        if is_encrypted:
            if sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
                details.append(['Encryption', 'TLS/SSL'])
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    if len(payload) >= 5:
                        version = struct.unpack('!H', payload[1:3])[0]
                        ver_name = TLS_VERSIONS.get(version, f'0x{version:04x}')
                        details.append(['TLS Version', ver_name])
                        content_type = payload[0]
                        ct_name = TLS_CONTENT_TYPES.get(content_type, f'{content_type}')
                        details.append(['Content Type', ct_name])
            elif sport == 22 or dport == 22:
                details.append(['Encryption', 'SSH Protocol'])
            else:
                details.append(['Encryption', 'TLS (Secure Port)'])
            details.append(['Data Format', 'Encrypted Binary'])
            details.append(['Compression', 'N/A (Encrypted)'])
        else:
            details.append(['Encryption', 'None (Plaintext)'])
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                # Detect format
                fmt = 'Binary'
                if payload[:5] == b'<?xml' or payload[:6] == b'<?XML ':
                    fmt = 'XML'
                elif payload[:1] in (b'{', b'['):
                    fmt = 'JSON'
                elif payload[:5] == b'<!DOC' or payload[:6].lower() == b'<html>':
                    fmt = 'HTML'
                elif payload[:4] == b'HTTP' or payload[:3] in (b'GET', b'POS', b'PUT', b'DEL'):
                    fmt = 'HTTP Text'
                elif all(32 <= b < 127 or b in (9, 10, 13) for b in payload[:50]):
                    fmt = 'ASCII Text'
                details.append(['Data Format', fmt])
                
                # Compression detection
                comp = 'None'
                if payload[:2] == b'\x1f\x8b':
                    comp = 'GZIP'
                elif payload[:4] == b'PK\x03\x04':
                    comp = 'ZIP'
                elif payload[:3] == b'BZh':
                    comp = 'BZIP2'
                details.append(['Compression', comp])
                
                # Encoding detection
                enc = 'ASCII'
                if payload[:3] == b'\xef\xbb\xbf':
                    enc = 'UTF-8 (BOM)'
                elif payload[:2] == b'\xff\xfe':
                    enc = 'UTF-16 LE'
                elif payload[:2] == b'\xfe\xff':
                    enc = 'UTF-16 BE'
                else:
                    try:
                        payload[:100].decode('utf-8')
                        enc = 'UTF-8'
                    except:
                        enc = 'Binary/Unknown'
                details.append(['Character Encoding', enc])
            else:
                details.append(['Data Format', 'No payload'])

        # === Layer 7: Application ===
        details.append(['=== Layer 7: Application ===', ''])
        app_proto = PacketParser._detect_app_protocol(packet, sport, dport) or 'Unknown'
        details.append(['Protocol', app_proto])
        port_info = WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport)
        if port_info:
            details.append(['Service', port_info])
        
        # Protocol-specific parsing using external parsers
        if DNS in packet or sport == 53 or dport == 53:
            parse_dns_app(packet, details)
        elif sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
            parse_http_app(packet, details)
        elif sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
            parse_tls_app(packet, details)
        elif sport in (67, 68) or dport in (67, 68):
            parse_dhcp_app(packet, details)
        elif sport == 21 or dport == 21:
            parse_ftp_app(packet, details)
        elif sport == 25 or dport == 25 or sport == 587 or dport == 587 or sport == 465 or dport == 465:
            parse_smtp_app(packet, details)
        elif sport == 22 or dport == 22:
            parse_ssh_app(packet, details)
        elif sport == 110 or dport == 110 or sport == 995 or dport == 995:
            parse_pop3_app(packet, details)
        elif sport == 143 or dport == 143 or sport == 993 or dport == 993:
            parse_imap_app(packet, details)
        elif sport == 123 or dport == 123:
            parse_ntp_app(packet, details)
        elif sport == 161 or dport == 161 or sport == 162 or dport == 162:
            parse_snmp_app(packet, details)
        elif sport == 23 or dport == 23:
            parse_telnet_app(packet, details)
        elif Raw in packet:
            parse_raw_data(packet, details)
        
        return details