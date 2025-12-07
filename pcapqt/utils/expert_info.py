# -*- coding: utf-8 -*-
"""
Expert info module for packet analysis.
Provides severity-based information about packet issues.
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Optional


class Severity(Enum):
    """Severity levels for expert info."""
    ERROR = 'error'       # Serious issues (checksum failures, malformed packets)
    WARNING = 'warning'   # Potential issues (retransmissions, resets)
    NOTE = 'note'         # Informational (connection state changes)
    CHAT = 'chat'         # Protocol details (sequence numbers, etc.)


@dataclass
class ExpertInfo:
    """Single expert info entry."""
    severity: Severity
    protocol: str
    summary: str
    packet_number: int
    group: str = ""  # Group category
    
    def to_dict(self):
        return {
            'severity': self.severity.value,
            'protocol': self.protocol,
            'summary': self.summary,
            'packet': self.packet_number,
            'group': self.group
        }


class ExpertInfoCollector:
    """Collect and manage expert info entries."""
    
    GROUPS = {
        'checksum': 'Checksum',
        'sequence': 'Sequence',
        'protocol': 'Protocol',
        'malformed': 'Malformed',
        'reassembly': 'Reassembly',
        'request_response': 'Request/Response',
    }
    
    def __init__(self):
        self.entries: List[ExpertInfo] = []
    
    def reset(self):
        """Clear all entries."""
        self.entries.clear()
    
    def add_error(self, protocol: str, summary: str, packet_number: int, group: str = ""):
        """Add error-level info."""
        self.entries.append(ExpertInfo(
            Severity.ERROR, protocol, summary, packet_number, group
        ))
    
    def add_warning(self, protocol: str, summary: str, packet_number: int, group: str = ""):
        """Add warning-level info."""
        self.entries.append(ExpertInfo(
            Severity.WARNING, protocol, summary, packet_number, group
        ))
    
    def add_note(self, protocol: str, summary: str, packet_number: int, group: str = ""):
        """Add note-level info."""
        self.entries.append(ExpertInfo(
            Severity.NOTE, protocol, summary, packet_number, group
        ))
    
    def add_chat(self, protocol: str, summary: str, packet_number: int, group: str = ""):
        """Add chat-level info."""
        self.entries.append(ExpertInfo(
            Severity.CHAT, protocol, summary, packet_number, group
        ))
    
    def add_checksum_error(self, protocol: str, packet_number: int, expected: int, actual: int):
        """Add checksum validation error."""
        self.add_error(
            protocol,
            f"Bad checksum [expected 0x{expected:04x}, got 0x{actual:04x}]",
            packet_number,
            'checksum'
        )
    
    def add_tcp_retransmission(self, packet_number: int, seq: int):
        """Add TCP retransmission warning."""
        self.add_warning(
            'TCP',
            f"Retransmission (seq={seq})",
            packet_number,
            'sequence'
        )
    
    def add_tcp_out_of_order(self, packet_number: int, seq: int):
        """Add TCP out-of-order note."""
        self.add_note(
            'TCP',
            f"Out-of-order segment (seq={seq})",
            packet_number,
            'sequence'
        )
    
    def add_tcp_duplicate_ack(self, packet_number: int, ack: int, count: int):
        """Add TCP duplicate ACK note."""
        self.add_note(
            'TCP',
            f"Duplicate ACK #{count} (ack={ack})",
            packet_number,
            'sequence'
        )
    
    def add_tcp_zero_window(self, packet_number: int):
        """Add TCP zero window warning."""
        self.add_warning(
            'TCP',
            "Zero window",
            packet_number,
            'sequence'
        )
    
    def add_tcp_reset(self, packet_number: int):
        """Add TCP reset warning."""
        self.add_warning(
            'TCP',
            "Connection reset (RST)",
            packet_number,
            'sequence'
        )
    
    def get_all(self) -> List[ExpertInfo]:
        """Get all entries."""
        return self.entries
    
    def get_by_severity(self, severity: Severity) -> List[ExpertInfo]:
        """Get entries for a specific severity."""
        return [e for e in self.entries if e.severity == severity]
    
    def get_by_packet(self, packet_number: int) -> List[ExpertInfo]:
        """Get entries for a specific packet."""
        return [e for e in self.entries if e.packet_number == packet_number]
    
    def get_summary(self) -> dict:
        """Get count summary by severity."""
        summary = {s.value: 0 for s in Severity}
        for entry in self.entries:
            summary[entry.severity.value] += 1
        return summary
    
    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return any(e.severity == Severity.ERROR for e in self.entries)
    
    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return any(e.severity == Severity.WARNING for e in self.entries)
    
    def format_for_display(self, max_entries: Optional[int] = None) -> List[List[str]]:
        """
        Format entries for table display.
        
        Returns:
            List of [severity, protocol, packet, summary] rows
        """
        entries = self.entries[:max_entries] if max_entries else self.entries
        return [
            [e.severity.value.upper(), e.protocol, str(e.packet_number), e.summary]
            for e in entries
        ]
