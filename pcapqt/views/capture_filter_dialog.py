# -*- coding: utf-8 -*-
"""
Capture filter dialog for BPF filter input.
Allows setting packet capture filter before starting capture.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QGroupBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


class CaptureFilterDialog(QDialog):
    """Dialog for setting BPF capture filter."""
    
    # Common filter examples
    FILTER_EXAMPLES = [
        ("TCP only", "tcp"),
        ("UDP only", "udp"),
        ("Port 80", "port 80"),
        ("Port 443", "port 443"),
        ("Specific host", "host 192.168.1.1"),
        ("Specific network", "net 192.168.1.0/24"),
        ("TCP port range", "tcp portrange 80-8080"),
        ("Not broadcast", "not broadcast"),
        ("ICMP", "icmp"),
        ("ARP", "arp"),
    ]
    
    def __init__(self, current_filter="", parent=None):
        super().__init__(parent)
        self.filter_expression = current_filter
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Capture Filter")
        self.setMinimumSize(500, 350)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Info label
        info_label = QLabel(
            "Enter a BPF (Berkeley Packet Filter) expression to filter packets during capture.\n"
            "Only matching packets will be captured."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Filter input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Filter:"))
        
        self.filter_input = QLineEdit()
        self.filter_input.setFont(QFont("Consolas", 10))
        self.filter_input.setPlaceholderText("e.g., tcp port 80")
        self.filter_input.setText(self.filter_expression)
        input_layout.addWidget(self.filter_input)
        
        layout.addLayout(input_layout)
        
        # Examples group
        examples_group = QGroupBox("Filter Examples")
        examples_layout = QVBoxLayout(examples_group)
        
        examples_text = QTextEdit()
        examples_text.setReadOnly(True)
        examples_text.setMaximumHeight(150)
        examples_text.setFont(QFont("Consolas", 9))
        
        examples_content = []
        for name, expr in self.FILTER_EXAMPLES:
            examples_content.append(f"{name}: {expr}")
        examples_text.setPlainText("\n".join(examples_content))
        
        examples_layout.addWidget(examples_text)
        layout.addWidget(examples_group)
        
        # Syntax help
        help_label = QLabel(
            "Operators: and, or, not  |  "
            "Examples: 'tcp and port 80', 'host 10.0.0.1 or host 10.0.0.2'"
        )
        help_label.setStyleSheet("color: #666; font-size: 11px;")
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(lambda: self.filter_input.clear())
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        self.apply_btn = QPushButton("Apply")
        self.apply_btn.setDefault(True)
        self.apply_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.apply_btn)
        
        layout.addLayout(button_layout)
    
    def accept(self):
        """Store filter and close."""
        self.filter_expression = self.filter_input.text().strip()
        super().accept()
    
    def get_filter(self):
        """Get the filter expression."""
        return self.filter_expression
    
    @staticmethod
    def get_capture_filter(current_filter="", parent=None):
        """
        Static method to show dialog and get filter.
        
        Returns:
            Filter string or None if cancelled
        """
        dialog = CaptureFilterDialog(current_filter, parent)
        if dialog.exec_() == QDialog.Accepted:
            return dialog.get_filter()
        return None
