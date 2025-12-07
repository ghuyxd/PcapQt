# -*- coding: utf-8 -*-
"""
Packet coloring rules for different protocols.
Similar to Wireshark's coloring rules.
"""

from PyQt5.QtGui import QColor


class PacketColors:
    """Color definitions for different packet types."""
    
    # Protocol colors (similar to Wireshark defaults)
    COLORS = {
        # Transport protocols
        'TCP': QColor(231, 230, 255),       # Light purple
        'UDP': QColor(218, 238, 255),       # Light blue
        'ICMP': QColor(252, 224, 255),      # Light pink
        
        # Network protocols
        'ARP': QColor(250, 240, 215),       # Light yellow/tan
        'IPv6': QColor(230, 230, 230),      # Light gray
        
        # Application protocols - secure
        'TLS': QColor(231, 230, 255),       # Light purple
        'HTTPS': QColor(231, 230, 255),     # Light purple
        'SSH': QColor(231, 230, 255),       # Light purple
        
        # Application protocols - web
        'HTTP': QColor(228, 255, 199),      # Light green
        'DNS': QColor(218, 238, 255),       # Light blue
        'DHCP': QColor(218, 238, 255),      # Light blue
        
        # Application protocols - mail
        'SMTP': QColor(255, 253, 217),      # Light yellow
        'POP3': QColor(255, 253, 217),      # Light yellow
        'IMAP': QColor(255, 253, 217),      # Light yellow
        
        # Application protocols - file transfer
        'FTP': QColor(255, 239, 213),       # Peach
        'FTP-Data': QColor(255, 239, 213),  # Peach
        
        # Application protocols - other
        'Telnet': QColor(255, 245, 238),    # Seashell
        'NTP': QColor(218, 238, 255),       # Light blue
        'SNMP': QColor(255, 250, 205),      # Lemon chiffon
        
        # Error colors
        'RST': QColor(255, 199, 206),       # Light red (TCP Reset)
        'Error': QColor(255, 199, 206),     # Light red
        
        # Default
        'Default': QColor(255, 255, 255),   # White
    }
    
    # Background colors for special states
    SPECIAL_COLORS = {
        'Marked': QColor(0, 0, 0),          # Black background
        'Marked_FG': QColor(255, 255, 255), # White text for marked
        'Selected': QColor(51, 153, 255),   # Blue selection
        'Retransmission': QColor(255, 240, 240),  # Very light red
        'OutOfOrder': QColor(255, 250, 240),      # Light orange
        'DuplicateAck': QColor(255, 255, 230),    # Very light yellow
    }
    
    @classmethod
    def get_color(cls, protocol, tcp_flags=None):
        """
        Get background color for a protocol.
        
        Args:
            protocol: Protocol name string or protocol number
            tcp_flags: Optional TCP flags for special coloring
            
        Returns:
            QColor for the background
        """
        # Check for TCP RST flag
        if tcp_flags and 'RST' in str(tcp_flags):
            return cls.COLORS.get('RST', cls.COLORS['Default'])
        
        # Handle int protocol numbers
        if isinstance(protocol, int):
            protocol = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}.get(protocol, str(protocol))
        
        # Normalize protocol name
        proto_upper = str(protocol).upper() if protocol else ''
        
        # Try exact match first
        if proto_upper in cls.COLORS:
            return cls.COLORS[proto_upper]
        
        # Try partial matches
        for key in cls.COLORS:
            if key in proto_upper or proto_upper in key:
                return cls.COLORS[key]
        
        # Default color
        return cls.COLORS['Default']
    
    @classmethod
    def get_foreground(cls, protocol, is_marked=False):
        """
        Get foreground (text) color for a protocol.
        
        Args:
            protocol: Protocol name
            is_marked: Whether the packet is marked
            
        Returns:
            QColor for the text
        """
        if is_marked:
            return cls.SPECIAL_COLORS['Marked_FG']
        return QColor(0, 0, 0)  # Black text by default
    
    @classmethod
    def get_marked_background(cls):
        """Get background color for marked packets."""
        return cls.SPECIAL_COLORS['Marked']
    
    @classmethod
    def is_error_color(cls, protocol, tcp_flags=None):
        """Check if this packet should be colored as an error."""
        if tcp_flags and 'RST' in str(tcp_flags):
            return True
        proto_upper = protocol.upper() if protocol else ''
        return proto_upper in ('RST', 'ERROR')
