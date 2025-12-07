# -*- coding: utf-8 -*-
"""
Go to packet dialog.
Allows jumping to a specific packet number.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QSpinBox, QPushButton
)
from PyQt5.QtCore import Qt


class GotoDialog(QDialog):
    """Dialog for jumping to a specific packet number."""
    
    def __init__(self, current_packet=1, total_packets=1, parent=None):
        super().__init__(parent)
        self.target_packet = None
        self.setup_ui(current_packet, total_packets)
    
    def setup_ui(self, current_packet, total_packets):
        self.setWindowTitle("Go To Packet")
        self.setFixedSize(300, 120)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Input row
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Packet number:"))
        
        self.packet_spin = QSpinBox()
        self.packet_spin.setRange(1, max(1, total_packets))
        self.packet_spin.setValue(current_packet)
        self.packet_spin.setMinimumWidth(100)
        input_layout.addWidget(self.packet_spin)
        
        self.total_label = QLabel(f"/ {total_packets}")
        input_layout.addWidget(self.total_label)
        
        input_layout.addStretch()
        layout.addLayout(input_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.goto_btn = QPushButton("Go To")
        self.goto_btn.setDefault(True)
        self.goto_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.goto_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
    
    def accept(self):
        """Store target packet and close."""
        self.target_packet = self.packet_spin.value()
        super().accept()
    
    def get_target_packet(self):
        """Get the target packet number (1-indexed)."""
        return self.target_packet
    
    @staticmethod
    def get_packet_number(current=1, total=1, parent=None):
        """
        Static method to show dialog and get packet number.
        
        Returns:
            Packet number (1-indexed) or None if cancelled
        """
        dialog = GotoDialog(current, total, parent)
        if dialog.exec_() == QDialog.Accepted:
            return dialog.get_target_packet()
        return None
