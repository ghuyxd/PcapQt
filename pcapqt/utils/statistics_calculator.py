# -*- coding: utf-8 -*-
"""
Statistics calculator for packet captures.
Provides protocol hierarchy, conversations, endpoints, and capture statistics.
"""

from collections import defaultdict
from datetime import datetime
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, IPv6


class StatisticsCalculator:
    """Calculate various statistics from captured packets."""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset all statistics."""
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = None
        self.end_time = None
        
        # Protocol counters
        self.protocol_counts = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
        # Conversations: key = (addr_a, addr_b, port_a, port_b, proto)
        self.conversations = defaultdict(lambda: {
            'packets_ab': 0, 'packets_ba': 0,
            'bytes_ab': 0, 'bytes_ba': 0,
            'start_time': None, 'end_time': None
        })
        
        # Endpoints: key = (address, type)
        self.endpoints = defaultdict(lambda: {
            'tx_packets': 0, 'rx_packets': 0,
            'tx_bytes': 0, 'rx_bytes': 0
        })
        
        # Ethernet endpoints
        self.eth_endpoints = defaultdict(lambda: {
            'packets': 0, 'bytes': 0
        })
    
    def process_packet(self, packet, timestamp=None):
        """
        Process a single packet and update statistics.
        
        Args:
            packet: Scapy packet
            timestamp: Optional packet timestamp
        """
        self.total_packets += 1
        pkt_len = len(packet)
        self.total_bytes += pkt_len
        
        # Update time tracking
        ts = timestamp or datetime.now()
        if self.start_time is None:
            self.start_time = ts
        self.end_time = ts
        
        # Process layers
        self._process_ethernet(packet, pkt_len)
        self._process_network(packet, pkt_len, ts)
        self._process_transport(packet, pkt_len, ts)
    
    def _process_ethernet(self, packet, pkt_len):
        """Process Ethernet layer statistics."""
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
            self.eth_endpoints[src_mac]['packets'] += 1
            self.eth_endpoints[src_mac]['bytes'] += pkt_len
            self.eth_endpoints[dst_mac]['packets'] += 1
            self.eth_endpoints[dst_mac]['bytes'] += pkt_len
            
            self.protocol_counts['Ethernet']['packets'] += 1
            self.protocol_counts['Ethernet']['bytes'] += pkt_len
    
    def _process_network(self, packet, pkt_len, ts):
        """Process Network layer statistics."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # IP endpoints
            self.endpoints[(src_ip, 'IPv4')]['tx_packets'] += 1
            self.endpoints[(src_ip, 'IPv4')]['tx_bytes'] += pkt_len
            self.endpoints[(dst_ip, 'IPv4')]['rx_packets'] += 1
            self.endpoints[(dst_ip, 'IPv4')]['rx_bytes'] += pkt_len
            
            self.protocol_counts['IPv4']['packets'] += 1
            self.protocol_counts['IPv4']['bytes'] += pkt_len
            
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            
            self.endpoints[(src_ip, 'IPv6')]['tx_packets'] += 1
            self.endpoints[(src_ip, 'IPv6')]['tx_bytes'] += pkt_len
            self.endpoints[(dst_ip, 'IPv6')]['rx_packets'] += 1
            self.endpoints[(dst_ip, 'IPv6')]['rx_bytes'] += pkt_len
            
            self.protocol_counts['IPv6']['packets'] += 1
            self.protocol_counts['IPv6']['bytes'] += pkt_len
            
        elif ARP in packet:
            self.protocol_counts['ARP']['packets'] += 1
            self.protocol_counts['ARP']['bytes'] += pkt_len
    
    def _process_transport(self, packet, pkt_len, ts):
        """Process Transport layer statistics."""
        if IP not in packet and IPv6 not in packet:
            return
        
        ip_layer = packet[IP] if IP in packet else packet[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto = 'TCP'
            
            self.protocol_counts['TCP']['packets'] += 1
            self.protocol_counts['TCP']['bytes'] += pkt_len
            
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto = 'UDP'
            
            self.protocol_counts['UDP']['packets'] += 1
            self.protocol_counts['UDP']['bytes'] += pkt_len
            
        elif ICMP in packet:
            self.protocol_counts['ICMP']['packets'] += 1
            self.protocol_counts['ICMP']['bytes'] += pkt_len
            return
        else:
            return
        
        # Track conversation
        # Normalize key so A->B and B->A go to same conversation
        if (src_ip, sport) < (dst_ip, dport):
            key = (src_ip, dst_ip, sport, dport, proto)
            direction = 'ab'
        else:
            key = (dst_ip, src_ip, dport, sport, proto)
            direction = 'ba'
        
        conv = self.conversations[key]
        conv[f'packets_{direction}'] += 1
        conv[f'bytes_{direction}'] += pkt_len
        
        if conv['start_time'] is None:
            conv['start_time'] = ts
        conv['end_time'] = ts
    
    def get_capture_statistics(self):
        """
        Get overall capture statistics.
        
        Returns:
            dict with capture statistics
        """
        duration = 0
        if self.start_time and self.end_time:
            if isinstance(self.start_time, datetime):
                duration = (self.end_time - self.start_time).total_seconds()
            else:
                duration = self.end_time - self.start_time
        
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'duration': duration,
            'packets_per_sec': self.total_packets / duration if duration > 0 else 0,
            'bytes_per_sec': self.total_bytes / duration if duration > 0 else 0,
            'avg_packet_size': self.total_bytes / self.total_packets if self.total_packets > 0 else 0,
            'start_time': self.start_time,
            'end_time': self.end_time,
        }
    
    def get_protocol_hierarchy(self):
        """
        Get protocol hierarchy statistics.
        
        Returns:
            list of dicts with protocol stats
        """
        result = []
        for proto, stats in sorted(self.protocol_counts.items()):
            pct_packets = (stats['packets'] / self.total_packets * 100) if self.total_packets > 0 else 0
            pct_bytes = (stats['bytes'] / self.total_bytes * 100) if self.total_bytes > 0 else 0
            
            result.append({
                'protocol': proto,
                'packets': stats['packets'],
                'bytes': stats['bytes'],
                'percent_packets': pct_packets,
                'percent_bytes': pct_bytes,
            })
        
        # Sort by packet count descending
        result.sort(key=lambda x: x['packets'], reverse=True)
        return result
    
    def get_conversations(self, protocol=None):
        """
        Get conversation statistics.
        
        Args:
            protocol: Optional filter by protocol ('TCP', 'UDP', or None for all)
            
        Returns:
            list of conversation dicts
        """
        result = []
        for key, stats in self.conversations.items():
            addr_a, addr_b, port_a, port_b, proto = key
            
            if protocol and proto != protocol:
                continue
            
            total_packets = stats['packets_ab'] + stats['packets_ba']
            total_bytes = stats['bytes_ab'] + stats['bytes_ba']
            
            duration = 0
            if stats['start_time'] and stats['end_time']:
                if isinstance(stats['start_time'], datetime):
                    duration = (stats['end_time'] - stats['start_time']).total_seconds()
                else:
                    duration = stats['end_time'] - stats['start_time']
            
            result.append({
                'address_a': f"{addr_a}:{port_a}",
                'address_b': f"{addr_b}:{port_b}",
                'protocol': proto,
                'packets_ab': stats['packets_ab'],
                'packets_ba': stats['packets_ba'],
                'packets_total': total_packets,
                'bytes_ab': stats['bytes_ab'],
                'bytes_ba': stats['bytes_ba'],
                'bytes_total': total_bytes,
                'duration': duration,
            })
        
        # Sort by total packets descending
        result.sort(key=lambda x: x['packets_total'], reverse=True)
        return result
    
    def get_endpoints(self, endpoint_type=None):
        """
        Get endpoint statistics.
        
        Args:
            endpoint_type: Optional filter ('IPv4', 'IPv6', or None for all)
            
        Returns:
            list of endpoint dicts
        """
        result = []
        for (addr, addr_type), stats in self.endpoints.items():
            if endpoint_type and addr_type != endpoint_type:
                continue
            
            total_packets = stats['tx_packets'] + stats['rx_packets']
            total_bytes = stats['tx_bytes'] + stats['rx_bytes']
            
            result.append({
                'address': addr,
                'type': addr_type,
                'tx_packets': stats['tx_packets'],
                'rx_packets': stats['rx_packets'],
                'packets_total': total_packets,
                'tx_bytes': stats['tx_bytes'],
                'rx_bytes': stats['rx_bytes'],
                'bytes_total': total_bytes,
            })
        
        # Sort by total packets descending
        result.sort(key=lambda x: x['packets_total'], reverse=True)
        return result
    
    def get_ethernet_endpoints(self):
        """
        Get Ethernet endpoint statistics.
        
        Returns:
            list of Ethernet endpoint dicts
        """
        result = []
        for mac, stats in self.eth_endpoints.items():
            result.append({
                'address': mac,
                'packets': stats['packets'],
                'bytes': stats['bytes'],
            })
        
        result.sort(key=lambda x: x['packets'], reverse=True)
        return result
