# -*- coding: utf-8 -*-
"""
ICMPv6 protocol parser.
Parses ICMPv6 messages including Neighbor Discovery.
"""

from scapy.all import IPv6, Raw


# ICMPv6 Type codes
ICMPV6_TYPES = {
    1: 'Destination Unreachable',
    2: 'Packet Too Big',
    3: 'Time Exceeded',
    4: 'Parameter Problem',
    128: 'Echo Request',
    129: 'Echo Reply',
    130: 'Multicast Listener Query',
    131: 'Multicast Listener Report',
    132: 'Multicast Listener Done',
    133: 'Router Solicitation',
    134: 'Router Advertisement',
    135: 'Neighbor Solicitation',
    136: 'Neighbor Advertisement',
    137: 'Redirect',
    143: 'Multicast Listener Report v2',
}

# Destination Unreachable codes
DEST_UNREACHABLE_CODES = {
    0: 'No route to destination',
    1: 'Communication administratively prohibited',
    2: 'Beyond scope of source address',
    3: 'Address unreachable',
    4: 'Port unreachable',
    5: 'Source address failed policy',
    6: 'Reject route to destination',
}


def parse_icmpv6_details(packet, details):
    """
    Parse ICMPv6 message and add to details list.
    
    Args:
        packet: Scapy packet with ICMPv6 layer
        details: List to append detail rows to
    """
    # Try to import ICMPv6 layers
    try:
        from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply
        from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA
        from scapy.layers.inet6 import ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded
    except ImportError:
        return
    
    details.append(['=== Layer 4: ICMPv6 ===', ''])
    
    # Echo Request
    if ICMPv6EchoRequest in packet:
        icmp = packet[ICMPv6EchoRequest]
        details.append(['Type', '128 (Echo Request)'])
        details.append(['Code', icmp.code])
        details.append(['Identifier', icmp.id])
        details.append(['Sequence', icmp.seq])
        return
    
    # Echo Reply
    if ICMPv6EchoReply in packet:
        icmp = packet[ICMPv6EchoReply]
        details.append(['Type', '129 (Echo Reply)'])
        details.append(['Code', icmp.code])
        details.append(['Identifier', icmp.id])
        details.append(['Sequence', icmp.seq])
        return
    
    # Neighbor Solicitation
    if ICMPv6ND_NS in packet:
        icmp = packet[ICMPv6ND_NS]
        details.append(['Type', '135 (Neighbor Solicitation)'])
        details.append(['Target Address', icmp.tgt])
        return
    
    # Neighbor Advertisement
    if ICMPv6ND_NA in packet:
        icmp = packet[ICMPv6ND_NA]
        details.append(['Type', '136 (Neighbor Advertisement)'])
        details.append(['Target Address', icmp.tgt])
        details.append(['Router Flag', icmp.R])
        details.append(['Solicited Flag', icmp.S])
        details.append(['Override Flag', icmp.O])
        return
    
    # Router Solicitation
    if ICMPv6ND_RS in packet:
        details.append(['Type', '133 (Router Solicitation)'])
        return
    
    # Router Advertisement
    if ICMPv6ND_RA in packet:
        icmp = packet[ICMPv6ND_RA]
        details.append(['Type', '134 (Router Advertisement)'])
        details.append(['Hop Limit', icmp.chlim])
        details.append(['Router Lifetime', f"{icmp.routerlifetime} seconds"])
        return
    
    # Destination Unreachable
    if ICMPv6DestUnreach in packet:
        icmp = packet[ICMPv6DestUnreach]
        code_name = DEST_UNREACHABLE_CODES.get(icmp.code, f'Unknown ({icmp.code})')
        details.append(['Type', '1 (Destination Unreachable)'])
        details.append(['Code', f"{icmp.code} ({code_name})"])
        return
    
    # Packet Too Big
    if ICMPv6PacketTooBig in packet:
        icmp = packet[ICMPv6PacketTooBig]
        details.append(['Type', '2 (Packet Too Big)'])
        details.append(['MTU', icmp.mtu])
        return
    
    # Time Exceeded
    if ICMPv6TimeExceeded in packet:
        icmp = packet[ICMPv6TimeExceeded]
        details.append(['Type', '3 (Time Exceeded)'])
        details.append(['Code', icmp.code])
        return
    
    # Generic ICMPv6
    details.append(['Type', 'Unknown ICMPv6'])


def get_icmpv6_info(packet):
    """
    Get ICMPv6 message info string.
    
    Args:
        packet: Scapy packet
        
    Returns:
        Info string for display
    """
    try:
        from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply
        from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA
    except ImportError:
        return "ICMPv6"
    
    if ICMPv6EchoRequest in packet:
        return "Echo (ping) request"
    if ICMPv6EchoReply in packet:
        return "Echo (ping) reply"
    if ICMPv6ND_NS in packet:
        return f"Neighbor Solicitation for {packet[ICMPv6ND_NS].tgt}"
    if ICMPv6ND_NA in packet:
        return f"Neighbor Advertisement {packet[ICMPv6ND_NA].tgt}"
    
    return "ICMPv6"
