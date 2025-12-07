# -*- coding: utf-8 -*-
"""
Conversations dialog.
Shows all conversations (streams) between endpoints.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QTabWidget, QWidget, QHeaderView
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


class ConversationsDialog(QDialog):
    """Dialog for displaying conversation statistics."""
    
    def __init__(self, conversations, parent=None):
        super().__init__(parent)
        self.conversations = conversations
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Conversations")
        self.setMinimumSize(800, 500)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Tabs for different protocols
        self.tabs = QTabWidget()
        
        # TCP conversations
        tcp_convs = [c for c in self.conversations if c['protocol'] == 'TCP']
        if tcp_convs:
            tcp_widget = self._create_conversation_table(tcp_convs)
            self.tabs.addTab(tcp_widget, f"TCP ({len(tcp_convs)})")
        
        # UDP conversations
        udp_convs = [c for c in self.conversations if c['protocol'] == 'UDP']
        if udp_convs:
            udp_widget = self._create_conversation_table(udp_convs)
            self.tabs.addTab(udp_widget, f"UDP ({len(udp_convs)})")
        
        # All conversations
        all_widget = self._create_conversation_table(self.conversations)
        self.tabs.addTab(all_widget, f"All ({len(self.conversations)})")
        
        layout.addWidget(self.tabs)
        
        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def _create_conversation_table(self, conversations):
        """Create a table widget for conversations."""
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Address A", "Address B", "Packets A→B", "Packets B→A",
            "Bytes A→B", "Bytes B→A", "Total Packets", "Duration"
        ])
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setFont(QFont("Consolas", 9))
        table.setSortingEnabled(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        
        table.setRowCount(len(conversations))
        for row, conv in enumerate(conversations):
            table.setItem(row, 0, QTableWidgetItem(conv['address_a']))
            table.setItem(row, 1, QTableWidgetItem(conv['address_b']))
            table.setItem(row, 2, self._create_number_item(conv['packets_ab']))
            table.setItem(row, 3, self._create_number_item(conv['packets_ba']))
            table.setItem(row, 4, self._create_bytes_item(conv['bytes_ab']))
            table.setItem(row, 5, self._create_bytes_item(conv['bytes_ba']))
            table.setItem(row, 6, self._create_number_item(conv['packets_total']))
            table.setItem(row, 7, QTableWidgetItem(f"{conv['duration']:.2f}s"))
        
        return table
    
    def _create_number_item(self, value):
        """Create a right-aligned number item."""
        item = QTableWidgetItem(f"{value:,}")
        item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        item.setData(Qt.UserRole, value)  # For sorting
        return item
    
    def _create_bytes_item(self, bytes_val):
        """Create a right-aligned bytes item."""
        item = QTableWidgetItem(self._format_bytes(bytes_val))
        item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        item.setData(Qt.UserRole, bytes_val)  # For sorting
        return item
    
    def _format_bytes(self, bytes_val):
        """Format bytes to human-readable string."""
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        else:
            return f"{bytes_val / (1024 * 1024):.1f} MB"
