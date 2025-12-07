# -*- coding: utf-8 -*-
"""
IPv6 protocol parser.
Parses IPv6 headers and extension headers.
"""

from scapy.all import IPv6, Raw


# IPv6 Next Header values
IPV6_NEXT_HEADERS = {
    0: 'Hop-by-Hop Options',
    6: 'TCP',
    17: 'UDP',
    43: 'Routing',
    44: 'Fragment',
    50: 'ESP',
    51: 'AH',
    58: 'ICMPv6',
    59: 'No Next Header',
    60: 'Destination Options',
    135: 'Mobility',
    139: 'Host Identity Protocol',
    140: 'Shim6',
}


def parse_ipv6_details(packet, details):
    """
    Parse IPv6 header and add to details list.
    
    Args:
        packet: Scapy packet with IPv6 layer
        details: List to append detail rows to
    """
    if IPv6 not in packet:
        return
    
    ipv6 = packet[IPv6]
    
    details.append(['=== Layer 3: Network (IPv6) ===', ''])
    details.append(['Version', 6])
    details.append(['Traffic Class', f"0x{ipv6.tc:02x}"])
    details.append(['Flow Label', f"0x{ipv6.fl:05x}"])
    details.append(['Payload Length', f"{ipv6.plen} bytes"])
    
    nh = ipv6.nh
    nh_name = IPV6_NEXT_HEADERS.get(nh, f'Unknown ({nh})')
    details.append(['Next Header', f"{nh} ({nh_name})"])
    
    details.append(['Hop Limit', ipv6.hlim])
    details.append(['Source Address', ipv6.src])
    details.append(['Destination Address', ipv6.dst])


def get_ipv6_info(packet):
    """
    Get basic info for IPv6 packet.
    
    Args:
        packet: Scapy packet with IPv6 layer
        
    Returns:
        dict with src, dst, protocol info
    """
    if IPv6 not in packet:
        return None
    
    ipv6 = packet[IPv6]
    nh = ipv6.nh
    
    return {
        'src': ipv6.src,
        'dst': ipv6.dst,
        'next_header': nh,
        'next_header_name': IPV6_NEXT_HEADERS.get(nh, f'Unknown'),
        'hop_limit': ipv6.hlim,
        'payload_length': ipv6.plen,
    }
