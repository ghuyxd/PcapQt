# -*- coding: utf-8 -*-
"""Application layer protocol parsers."""

import struct
from scapy.all import Raw, DNS, DNSQR, DNSRR

from .constants import (
    DNS_TYPES,
    DNS_RCODES,
    DHCP_TYPES,
    TLS_HANDSHAKE_TYPES,
)


def parse_dns_app(packet, details):
    """Parse DNS protocol details."""
    if DNS in packet:
        dns = packet[DNS]
        qr = 'Response' if dns.qr else 'Query'
        details.append(['DNS Type', qr])
        details.append(['Transaction ID', f"0x{dns.id:04x}"])
        if dns.qdcount > 0 and DNSQR in packet:
            qname = packet[DNSQR].qname.decode() if isinstance(packet[DNSQR].qname, bytes) else str(packet[DNSQR].qname)
            qtype = DNS_TYPES.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))
            details.append(['Query', f"{qname} ({qtype})"])
        if dns.qr and dns.ancount > 0:
            details.append(['Answers', dns.ancount])
            if DNSRR in packet:
                try:
                    rr = dns.an[0] if hasattr(dns, 'an') else None
                    if rr and hasattr(rr, 'rdata'):
                        details.append(['First Answer', str(rr.rdata)])
                except:
                    pass
        details.append(['Response Code', DNS_RCODES.get(dns.rcode, str(dns.rcode))])


def parse_http_app(packet, details):
    """Parse HTTP protocol details."""
    if Raw not in packet:
        return
    try:
        payload = bytes(packet[Raw].load)
        text = payload.decode('utf-8', errors='replace')
        lines = text.split('\r\n')
        if not lines:
            return
        first = lines[0]
        if first.startswith('HTTP/'):
            parts = first.split(' ', 2)
            details.append(['HTTP Response', f"{parts[1]} {parts[2] if len(parts)>2 else ''}"])
        else:
            parts = first.split(' ')
            details.append(['HTTP Request', f"{parts[0]} {parts[1][:50] if len(parts)>1 else ''}"])
        # Show key headers
        for line in lines[1:6]:
            if ':' in line:
                k, v = line.split(':', 1)
                if k.strip().lower() in ('host', 'content-type', 'content-length', 'user-agent'):
                    details.append([k.strip(), v.strip()[:60]])
    except:
        pass


def parse_tls_app(packet, details):
    """Parse TLS/SSL protocol details."""
    if Raw not in packet:
        details.append(['TLS Status', 'Encrypted (no visible payload)'])
        return
    try:
        payload = bytes(packet[Raw].load)
        if len(payload) < 6:
            return
        content_type = payload[0]
        if content_type == 22:  # Handshake
            hs_type = payload[5]
            hs_name = TLS_HANDSHAKE_TYPES.get(hs_type, f'Type {hs_type}')
            details.append(['TLS Handshake', hs_name])
        elif content_type == 23:
            length = struct.unpack('!H', payload[3:5])[0]
            details.append(['Encrypted Data', f'{length} bytes'])
        elif content_type == 21:
            details.append(['TLS Alert', 'Alert message'])
    except:
        pass


def parse_dhcp_app(packet, details):
    """Parse DHCP protocol details."""
    if Raw not in packet:
        return
    try:
        payload = bytes(packet[Raw].load)
        if len(payload) < 240:
            return
        op = 'Request' if payload[0] == 1 else 'Reply' if payload[0] == 2 else 'Unknown'
        details.append(['DHCP Message', op])
        xid = struct.unpack('!I', payload[4:8])[0]
        details.append(['Transaction ID', f'0x{xid:08x}'])
        yiaddr = '.'.join(str(b) for b in payload[16:20])
        if yiaddr != '0.0.0.0':
            details.append(['Offered IP', yiaddr])
        # Parse DHCP message type option
        if len(payload) > 240 and payload[236:240] == b'\x63\x82\x53\x63':
            i = 240
            while i < len(payload) and payload[i] != 255:
                if payload[i] == 0:
                    i += 1
                    continue
                opt_code, opt_len = payload[i], payload[i+1]
                if opt_code == 53 and opt_len >= 1:
                    msg_type = DHCP_TYPES.get(payload[i+2], f'Type {payload[i+2]}')
                    details.append(['DHCP Type', msg_type])
                    break
                i += 2 + opt_len
    except:
        pass


def parse_ftp_app(packet, details):
    """Parse FTP protocol details."""
    if Raw not in packet:
        return
    try:
        text = bytes(packet[Raw].load).decode('utf-8', errors='replace').strip()
        lines = text.split('\r\n')
        for line in lines[:3]:
            if line[:3].isdigit():
                details.append(['FTP Response', line[:80]])
            else:
                parts = line.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1][:50] if len(parts) > 1 else ''
                details.append(['FTP Command', f"{cmd} {arg}"])
    except:
        pass


def parse_smtp_app(packet, details):
    """Parse SMTP protocol details."""
    if Raw not in packet:
        return
    try:
        text = bytes(packet[Raw].load).decode('utf-8', errors='replace').strip()
        lines = text.split('\r\n')
        for line in lines[:3]:
            if line[:3].isdigit():
                details.append(['SMTP Response', line[:80]])
            else:
                parts = line.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1][:50] if len(parts) > 1 else ''
                details.append(['SMTP Command', f"{cmd} {arg}"])
    except:
        pass


def parse_ssh_app(packet, details):
    """Parse SSH protocol details."""
    if Raw not in packet:
        details.append(['SSH Status', 'Encrypted session'])
        return
    try:
        payload = bytes(packet[Raw].load)
        if payload.startswith(b'SSH-'):
            text = payload.decode('utf-8', errors='replace')
            version_line = text.split('\n')[0].strip()
            details.append(['SSH Version', version_line])
        else:
            details.append(['SSH Status', 'Encrypted packet'])
    except:
        pass


def parse_pop3_app(packet, details):
    """Parse POP3 protocol details."""
    if Raw not in packet:
        return
    try:
        text = bytes(packet[Raw].load).decode('utf-8', errors='replace').strip()
        lines = text.split('\r\n')
        for line in lines[:3]:
            if line.startswith('+OK'):
                details.append(['POP3 Response', f"+OK {line[4:60]}"])
            elif line.startswith('-ERR'):
                details.append(['POP3 Error', f"-ERR {line[5:60]}"])
            else:
                parts = line.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1][:50] if len(parts) > 1 else ''
                if cmd in ('USER', 'PASS', 'LIST', 'RETR', 'DELE', 'QUIT', 'STAT', 'TOP', 'UIDL', 'NOOP', 'RSET'):
                    details.append(['POP3 Command', f"{cmd} {arg}"])
    except:
        pass


def parse_imap_app(packet, details):
    """Parse IMAP protocol details."""
    if Raw not in packet:
        return
    try:
        text = bytes(packet[Raw].load).decode('utf-8', errors='replace').strip()
        lines = text.split('\r\n')
        for line in lines[:3]:
            if '* OK' in line or '* NO' in line or '* BAD' in line:
                details.append(['IMAP Response', line[:80]])
            else:
                parts = line.split(' ', 2)
                if len(parts) >= 2:
                    tag = parts[0]
                    cmd = parts[1].upper()
                    arg = parts[2][:40] if len(parts) > 2 else ''
                    if cmd in ('LOGIN', 'SELECT', 'FETCH', 'SEARCH', 'LOGOUT', 'LIST', 'EXAMINE', 'CREATE', 'DELETE', 'STORE'):
                        details.append(['IMAP Command', f"{tag} {cmd} {arg}"])
    except:
        pass


def parse_ntp_app(packet, details):
    """Parse NTP protocol details."""
    if Raw not in packet:
        return
    try:
        payload = bytes(packet[Raw].load)
        if len(payload) < 48:
            return
        
        # NTP packet structure
        flags = payload[0]
        leap = (flags >> 6) & 0x03
        version = (flags >> 3) & 0x07
        mode = flags & 0x07
        
        mode_names = {
            0: 'Reserved', 1: 'Symmetric Active', 2: 'Symmetric Passive',
            3: 'Client', 4: 'Server', 5: 'Broadcast', 6: 'Control', 7: 'Private'
        }
        
        details.append(['NTP Version', version])
        details.append(['NTP Mode', f"{mode} ({mode_names.get(mode, 'Unknown')})"])
        details.append(['Stratum', payload[1]])
        details.append(['Poll Interval', f"{2 ** payload[2]} seconds"])
    except:
        pass


def parse_snmp_app(packet, details):
    """Parse SNMP protocol details."""
    if Raw not in packet:
        return
    try:
        payload = bytes(packet[Raw].load)
        if len(payload) < 10:
            return
        
        # Basic SNMP parsing (ASN.1 BER encoded)
        if payload[0] == 0x30:  # SEQUENCE
            # Try to find version
            if payload[2] == 0x02:  # INTEGER (version)
                version = payload[4]
                version_names = {0: 'SNMPv1', 1: 'SNMPv2c', 3: 'SNMPv3'}
                details.append(['SNMP Version', version_names.get(version, f'v{version}')])
            
            # Try to find community string for v1/v2c
            if version in (0, 1):
                idx = 5
                if idx < len(payload) and payload[idx] == 0x04:  # OCTET STRING
                    comm_len = payload[idx + 1]
                    if idx + 2 + comm_len <= len(payload):
                        community = payload[idx + 2:idx + 2 + comm_len].decode('utf-8', errors='replace')
                        details.append(['Community', community[:30]])
    except:
        pass


def parse_telnet_app(packet, details):
    """Parse Telnet protocol details."""
    if Raw not in packet:
        return
    try:
        payload = bytes(packet[Raw].load)
        
        # Check for Telnet IAC commands
        if payload and payload[0] == 0xFF:  # IAC
            iac_commands = {
                240: 'SE', 241: 'NOP', 242: 'Data Mark', 243: 'Break',
                244: 'Interrupt', 245: 'Abort', 246: 'Are You There',
                247: 'Erase Char', 248: 'Erase Line', 249: 'Go Ahead',
                250: 'SB', 251: 'WILL', 252: 'WONT', 253: 'DO', 254: 'DONT'
            }
            if len(payload) >= 2:
                cmd = payload[1]
                cmd_name = iac_commands.get(cmd, f'Unknown ({cmd})')
                details.append(['Telnet Command', f"IAC {cmd_name}"])
        else:
            # Regular text data
            text = payload.decode('utf-8', errors='replace')
            if text.strip():
                details.append(['Telnet Data', text[:60].strip()])
    except:
        pass


def parse_raw_data(packet, details):
    """Parse raw packet data."""
    if Raw not in packet:
        return
    raw_data = bytes(packet[Raw].load)
    details.append(['--- Raw Data ---', ''])
    details.append(['Payload Length', f"{len(raw_data)} bytes"])
    preview_len = min(64, len(raw_data))
    hex_preview = ' '.join(f"{b:02x}" for b in raw_data[:preview_len])
    if len(raw_data) > preview_len:
        hex_preview += '...'
    details.append(['Hex', hex_preview])
    ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_data[:preview_len])
    if len(raw_data) > preview_len:
        ascii_preview += '...'
    details.append(['ASCII', ascii_preview])
