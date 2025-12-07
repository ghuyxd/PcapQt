# -*- coding: utf-8 -*-
"""
TCP analyzer for detecting retransmissions, duplicates, and other issues.
Tracks TCP connection states and analyzes packet sequences.
"""

from collections import defaultdict
from scapy.all import TCP, IP


class TCPAnalyzer:
    """Analyze TCP packets for issues like retransmissions."""
    
    # TCP flags
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset analyzer state."""
        # Track last seen sequence/ack for each direction
        # Key: (src_ip, dst_ip, src_port, dst_port)
        self.last_seq = {}
        self.last_ack = {}
        self.seen_packets = {}  # For detecting duplicates
        self.connection_states = {}  # Track TCP state machine
        self.window_sizes = {}  # Track window sizes
        self.issues = []  # List of detected issues
    
    def analyze_packet(self, packet, packet_number):
        """
        Analyze a single TCP packet and return any detected issues.
        
        Args:
            packet: Scapy packet with TCP layer
            packet_number: Packet sequence number (1-indexed)
            
        Returns:
            list of issue dictionaries with 'type', 'severity', 'description'
        """
        if IP not in packet or TCP not in packet:
            return []
        
        issues = []
        
        ip = packet[IP]
        tcp = packet[TCP]
        
        # Create flow key (bidirectional)
        flow_key = self._get_flow_key(ip.src, ip.dst, tcp.sport, tcp.dport)
        direction_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        
        seq = tcp.seq
        ack = tcp.ack
        flags = tcp.flags
        window = tcp.window
        payload_len = len(tcp.payload) if tcp.payload else 0
        
        # Check for retransmission
        if direction_key in self.last_seq:
            last_seq = self.last_seq[direction_key]
            if seq < last_seq and not (flags & self.SYN) and not (flags & self.RST):
                if payload_len > 0:
                    issues.append({
                        'type': 'retransmission',
                        'severity': 'warning',
                        'description': f'TCP Retransmission (seq={seq}, expected>={last_seq})',
                        'packet': packet_number
                    })
        
        # Check for out-of-order
        if direction_key in self.last_seq:
            last_seq = self.last_seq[direction_key]
            expected_seq = last_seq + self.seen_packets.get(direction_key, {}).get('last_len', 0)
            if seq > expected_seq and payload_len > 0:
                issues.append({
                    'type': 'out_of_order',
                    'severity': 'note',
                    'description': f'TCP Out-Of-Order (seq={seq}, expected={expected_seq})',
                    'packet': packet_number
                })
        
        # Check for duplicate ACK
        reverse_key = (ip.dst, ip.src, tcp.dport, tcp.sport)
        if reverse_key in self.last_ack:
            last_ack_seen = self.last_ack[reverse_key]
            if ack == last_ack_seen and (flags & self.ACK) and payload_len == 0:
                dup_count = self.seen_packets.get(direction_key, {}).get('dup_ack_count', 0) + 1
                if dup_count >= 2:
                    issues.append({
                        'type': 'duplicate_ack',
                        'severity': 'note',
                        'description': f'TCP Duplicate ACK #{dup_count} (ack={ack})',
                        'packet': packet_number
                    })
                if direction_key not in self.seen_packets:
                    self.seen_packets[direction_key] = {}
                self.seen_packets[direction_key]['dup_ack_count'] = dup_count
            else:
                if direction_key in self.seen_packets:
                    self.seen_packets[direction_key]['dup_ack_count'] = 0
        
        # Check for zero window
        if window == 0 and (flags & self.ACK):
            issues.append({
                'type': 'zero_window',
                'severity': 'warning',
                'description': 'TCP Zero Window',
                'packet': packet_number
            })
        
        # Check for window update
        if direction_key in self.window_sizes:
            last_window = self.window_sizes[direction_key]
            if last_window == 0 and window > 0:
                issues.append({
                    'type': 'window_update',
                    'severity': 'note',
                    'description': f'TCP Window Update ({window})',
                    'packet': packet_number
                })
        
        # Check for RST
        if flags & self.RST:
            issues.append({
                'type': 'reset',
                'severity': 'warning',
                'description': 'TCP Connection Reset',
                'packet': packet_number
            })
        
        # Update tracking state
        self.last_seq[direction_key] = seq
        self.last_ack[direction_key] = ack
        self.window_sizes[direction_key] = window
        if direction_key not in self.seen_packets:
            self.seen_packets[direction_key] = {}
        self.seen_packets[direction_key]['last_len'] = payload_len
        
        # Track connection state
        self._update_connection_state(flow_key, direction_key, flags)
        
        # Store issues
        self.issues.extend(issues)
        
        return issues
    
    def _get_flow_key(self, src_ip, dst_ip, src_port, dst_port):
        """Get normalized flow key (same for both directions)."""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port)
        return (dst_ip, src_ip, dst_port, src_port)
    
    def _update_connection_state(self, flow_key, direction_key, flags):
        """Update TCP connection state machine."""
        current_state = self.connection_states.get(flow_key, 'CLOSED')
        
        if flags & self.SYN and not (flags & self.ACK):
            self.connection_states[flow_key] = 'SYN_SENT'
        elif flags & self.SYN and flags & self.ACK:
            self.connection_states[flow_key] = 'SYN_RECEIVED'
        elif flags & self.ACK and current_state == 'SYN_RECEIVED':
            self.connection_states[flow_key] = 'ESTABLISHED'
        elif flags & self.FIN:
            if current_state == 'ESTABLISHED':
                self.connection_states[flow_key] = 'FIN_WAIT_1'
            elif current_state == 'FIN_WAIT_1':
                self.connection_states[flow_key] = 'CLOSING'
        elif flags & self.RST:
            self.connection_states[flow_key] = 'CLOSED'
    
    def get_connection_state(self, packet):
        """Get current connection state for a packet."""
        if IP not in packet or TCP not in packet:
            return None
        
        flow_key = self._get_flow_key(
            packet[IP].src, packet[IP].dst,
            packet[TCP].sport, packet[TCP].dport
        )
        return self.connection_states.get(flow_key, 'UNKNOWN')
    
    def get_all_issues(self):
        """Get all detected issues."""
        return self.issues
    
    def get_issues_summary(self):
        """Get summary of detected issues."""
        summary = defaultdict(int)
        for issue in self.issues:
            summary[issue['type']] += 1
        return dict(summary)
