# -*- coding: utf-8 -*-
"""
Protocol hierarchy dialog.
Shows tree of protocols with packet/byte counts and percentages.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTreeWidget, QTreeWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


class ProtocolHierarchyDialog(QDialog):
    """Dialog for displaying protocol hierarchy statistics."""
    
    def __init__(self, protocol_stats, total_packets, total_bytes, parent=None):
        super().__init__(parent)
        self.protocol_stats = protocol_stats
        self.total_packets = total_packets
        self.total_bytes = total_bytes
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Protocol Hierarchy Statistics")
        self.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Summary
        summary = QLabel(f"Total: {self.total_packets:,} packets, {self._format_bytes(self.total_bytes)}")
        summary.setFont(QFont("Segoe UI", 10))
        layout.addWidget(summary)
        
        # Protocol tree
        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["Protocol", "Packets", "% Packets", "Bytes", "% Bytes"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setFont(QFont("Segoe UI", 9))
        
        # Set column widths
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        
        self._populate_tree()
        layout.addWidget(self.tree)
        
        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def _populate_tree(self):
        """Populate the protocol tree."""
        # Build hierarchy (simplified - flat list for now)
        for stat in self.protocol_stats:
            item = QTreeWidgetItem()
            item.setText(0, stat['protocol'])
            item.setText(1, f"{stat['packets']:,}")
            item.setText(2, f"{stat['percent_packets']:.1f}%")
            item.setText(3, self._format_bytes(stat['bytes']))
            item.setText(4, f"{stat['percent_bytes']:.1f}%")
            
            # Right-align numbers
            for col in range(1, 5):
                item.setTextAlignment(col, Qt.AlignRight | Qt.AlignVCenter)
            
            self.tree.addTopLevelItem(item)
        
        self.tree.expandAll()
    
    def _format_bytes(self, bytes_val):
        """Format bytes to human-readable string."""
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"
