# -*- coding: utf-8 -*-
"""
Statistics dialog showing capture statistics.
Displays packet counts, bytes, duration, and rates.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QGroupBox, QGridLayout
)
from PyQt5.QtGui import QFont

from ..utils.helpers import format_bytes, format_duration


class StatisticsDialog(QDialog):
    """Dialog for displaying capture statistics."""
    
    def __init__(self, statistics, parent=None):
        super().__init__(parent)
        self.stats = statistics
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Capture Statistics")
        self.setMinimumSize(400, 300)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # General statistics group
        general_group = QGroupBox("Capture Statistics")
        general_layout = QGridLayout(general_group)
        general_layout.setSpacing(8)
        
        stats_data = [
            ("Total Packets:", f"{self.stats.get('total_packets', 0):,}"),
            ("Total Bytes:", format_bytes(self.stats.get('total_bytes', 0))),
            ("Capture Duration:", format_duration(self.stats.get('duration', 0))),
            ("Average Packets/sec:", f"{self.stats.get('packets_per_sec', 0):.2f}"),
            ("Average Bytes/sec:", format_bytes(self.stats.get('bytes_per_sec', 0)) + "/s"),
            ("Average Packet Size:", f"{self.stats.get('avg_packet_size', 0):.1f} bytes"),
        ]
        
        for i, (label, value) in enumerate(stats_data):
            label_widget = QLabel(label)
            label_widget.setStyleSheet("font-weight: bold;")
            general_layout.addWidget(label_widget, i, 0)
            
            value_widget = QLabel(value)
            value_widget.setFont(QFont("Consolas", 10))
            general_layout.addWidget(value_widget, i, 1)
        
        layout.addWidget(general_group)
        
        # Time group
        time_group = QGroupBox("Time")
        time_layout = QGridLayout(time_group)
        
        start_time = self.stats.get('start_time')
        end_time = self.stats.get('end_time')
        
        time_layout.addWidget(QLabel("Start Time:"), 0, 0)
        time_layout.addWidget(QLabel(str(start_time) if start_time else "N/A"), 0, 1)
        
        time_layout.addWidget(QLabel("End Time:"), 1, 0)
        time_layout.addWidget(QLabel(str(end_time) if end_time else "N/A"), 1, 1)
        
        layout.addWidget(time_group)
        
        layout.addStretch()
        
        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
