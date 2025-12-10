# -*- coding: utf-8 -*-
"""
Shared helper utilities for dialogs and widgets.
Centralizes common formatting and widget creation functions.
"""

from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5.QtCore import Qt


def format_bytes(bytes_val: int, precision: int = 1) -> str:
    """
    Format bytes to human-readable string.
    
    Args:
        bytes_val: Number of bytes
        precision: Decimal places for KB/MB/GB
        
    Returns:
        Formatted string like "1.5 KB", "2.3 MB", etc.
    """
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.{precision}f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.{precision}f} MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.{precision}f} GB"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string like "500 ms", "2.00 seconds", "1m 30.0s", etc.
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.1f}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def create_number_item(value: int) -> QTableWidgetItem:
    """
    Create a right-aligned, sortable number item for tables.
    
    Args:
        value: Integer value to display
        
    Returns:
        QTableWidgetItem configured for number display
    """
    item = QTableWidgetItem(f"{value:,}")
    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
    item.setData(Qt.UserRole, value)  # Store raw value for sorting
    return item


def create_bytes_item(bytes_val: int, precision: int = 1) -> QTableWidgetItem:
    """
    Create a right-aligned, sortable bytes item for tables.
    
    Args:
        bytes_val: Bytes value to display
        precision: Decimal places for formatting
        
    Returns:
        QTableWidgetItem configured for bytes display
    """
    item = QTableWidgetItem(format_bytes(bytes_val, precision))
    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
    item.setData(Qt.UserRole, bytes_val)  # Store raw value for sorting
    return item


def normalize_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int):
    """
    Normalize flow key so both directions map to same key.
    
    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port
        dst_port: Destination port
        
    Returns:
        Tuple (ip1, ip2, port1, port2) in normalized order
    """
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port)
    return (dst_ip, src_ip, dst_port, src_port)
