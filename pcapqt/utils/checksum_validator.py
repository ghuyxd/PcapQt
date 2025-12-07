# -*- coding: utf-8 -*-
"""
Checksum validator for verifying packet checksums.
Supports IP, TCP, UDP, and ICMP checksums.
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw
import struct


class ChecksumValidator:
    """Validate packet checksums."""
    
    @staticmethod
    def calculate_ip_checksum(header_bytes):
        """
        Calculate IP header checksum.
        
        Args:
            header_bytes: IP header as bytes (with checksum field zeroed)
            
        Returns:
            Calculated checksum value
        """
        if len(header_bytes) < 20:
            return 0
        
        # Sum all 16-bit words
        checksum = 0
        for i in range(0, len(header_bytes), 2):
            if i + 1 < len(header_bytes):
                word = (header_bytes[i] << 8) + header_bytes[i + 1]
            else:
                word = header_bytes[i] << 8
            checksum += word
        
        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # One's complement
        return (~checksum) & 0xFFFF
    
    @staticmethod
    def verify_ip_checksum(packet):
        """
        Verify IP header checksum.
        
        Args:
            packet: Scapy packet with IP layer
            
        Returns:
            dict with 'valid', 'expected', 'actual' keys
        """
        if IP not in packet:
            return {'valid': None, 'error': 'No IP layer'}
        
        ip = packet[IP]
        actual = ip.chksum
        
        # Build header with checksum zeroed
        header_len = ip.ihl * 4
        raw_ip = bytes(ip)[:header_len]
        
        # Zero out checksum field (bytes 10-11)
        zeroed_header = raw_ip[:10] + b'\x00\x00' + raw_ip[12:]
        
        expected = ChecksumValidator.calculate_ip_checksum(zeroed_header)
        
        return {
            'valid': actual == expected,
            'expected': expected,
            'actual': actual
        }
    
    @staticmethod
    def calculate_pseudo_header_sum(src_ip, dst_ip, protocol, length):
        """Calculate pseudo header sum for TCP/UDP checksum."""
        # Convert IP addresses to integers
        src_parts = [int(x) for x in src_ip.split('.')]
        dst_parts = [int(x) for x in dst_ip.split('.')]
        
        pseudo = struct.pack('!BBBBBBBBBBH',
            src_parts[0], src_parts[1], src_parts[2], src_parts[3],
            dst_parts[0], dst_parts[1], dst_parts[2], dst_parts[3],
            0, protocol, length
        )
        
        checksum = 0
        for i in range(0, len(pseudo), 2):
            word = (pseudo[i] << 8) + pseudo[i + 1]
            checksum += word
        
        return checksum
    
    @staticmethod
    def verify_tcp_checksum(packet):
        """
        Verify TCP checksum.
        
        Args:
            packet: Scapy packet with TCP layer
            
        Returns:
            dict with 'valid', 'expected', 'actual' keys
        """
        if IP not in packet or TCP not in packet:
            return {'valid': None, 'error': 'No IP/TCP layer'}
        
        ip = packet[IP]
        tcp = packet[TCP]
        
        actual = tcp.chksum
        
        # Get TCP segment bytes
        tcp_bytes = bytes(tcp)
        tcp_len = len(tcp_bytes)
        
        # Calculate pseudo header sum
        pseudo_sum = ChecksumValidator.calculate_pseudo_header_sum(
            ip.src, ip.dst, 6, tcp_len  # 6 = TCP protocol
        )
        
        # Zero out checksum field
        tcp_zeroed = tcp_bytes[:16] + b'\x00\x00' + tcp_bytes[18:]
        
        # Add TCP segment
        checksum = pseudo_sum
        for i in range(0, len(tcp_zeroed), 2):
            if i + 1 < len(tcp_zeroed):
                word = (tcp_zeroed[i] << 8) + tcp_zeroed[i + 1]
            else:
                word = tcp_zeroed[i] << 8
            checksum += word
        
        # Fold carries
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        expected = (~checksum) & 0xFFFF
        
        return {
            'valid': actual == expected,
            'expected': expected,
            'actual': actual
        }
    
    @staticmethod
    def verify_udp_checksum(packet):
        """
        Verify UDP checksum.
        
        Args:
            packet: Scapy packet with UDP layer
            
        Returns:
            dict with 'valid', 'expected', 'actual' keys
        """
        if IP not in packet or UDP not in packet:
            return {'valid': None, 'error': 'No IP/UDP layer'}
        
        ip = packet[IP]
        udp = packet[UDP]
        
        actual = udp.chksum
        
        # UDP checksum 0 means not computed
        if actual == 0:
            return {'valid': True, 'expected': 0, 'actual': 0, 'note': 'Checksum not computed'}
        
        # Get UDP datagram bytes
        udp_bytes = bytes(udp)
        udp_len = len(udp_bytes)
        
        # Calculate pseudo header sum
        pseudo_sum = ChecksumValidator.calculate_pseudo_header_sum(
            ip.src, ip.dst, 17, udp_len  # 17 = UDP protocol
        )
        
        # Zero out checksum field
        udp_zeroed = udp_bytes[:6] + b'\x00\x00' + udp_bytes[8:]
        
        # Add UDP datagram
        checksum = pseudo_sum
        for i in range(0, len(udp_zeroed), 2):
            if i + 1 < len(udp_zeroed):
                word = (udp_zeroed[i] << 8) + udp_zeroed[i + 1]
            else:
                word = udp_zeroed[i] << 8
            checksum += word
        
        # Fold carries
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        expected = (~checksum) & 0xFFFF
        if expected == 0:
            expected = 0xFFFF  # UDP uses 0xFFFF instead of 0
        
        return {
            'valid': actual == expected,
            'expected': expected,
            'actual': actual
        }
    
    @staticmethod
    def verify_icmp_checksum(packet):
        """
        Verify ICMP checksum.
        
        Args:
            packet: Scapy packet with ICMP layer
            
        Returns:
            dict with 'valid', 'expected', 'actual' keys
        """
        if ICMP not in packet:
            return {'valid': None, 'error': 'No ICMP layer'}
        
        icmp = packet[ICMP]
        actual = icmp.chksum
        
        # Get ICMP bytes
        icmp_bytes = bytes(icmp)
        
        # Zero out checksum field
        icmp_zeroed = icmp_bytes[:2] + b'\x00\x00' + icmp_bytes[4:]
        
        # Calculate checksum
        checksum = 0
        for i in range(0, len(icmp_zeroed), 2):
            if i + 1 < len(icmp_zeroed):
                word = (icmp_zeroed[i] << 8) + icmp_zeroed[i + 1]
            else:
                word = icmp_zeroed[i] << 8
            checksum += word
        
        # Fold carries
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        expected = (~checksum) & 0xFFFF
        
        return {
            'valid': actual == expected,
            'expected': expected,
            'actual': actual
        }
    
    @staticmethod
    def verify_all_checksums(packet):
        """
        Verify all applicable checksums for a packet.
        
        Args:
            packet: Scapy packet
            
        Returns:
            dict with results for each layer
        """
        results = {}
        
        if IP in packet:
            results['ip'] = ChecksumValidator.verify_ip_checksum(packet)
        
        if TCP in packet:
            results['tcp'] = ChecksumValidator.verify_tcp_checksum(packet)
        
        if UDP in packet:
            results['udp'] = ChecksumValidator.verify_udp_checksum(packet)
        
        if ICMP in packet:
            results['icmp'] = ChecksumValidator.verify_icmp_checksum(packet)
        
        return results
