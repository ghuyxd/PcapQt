# -*- coding: utf-8 -*-
"""
Find dialog for searching packets.
Supports string, hex, and regex search.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QComboBox, QCheckBox, QGroupBox, QRadioButton
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
import re


class FindDialog(QDialog):
    """Dialog for finding packets by content."""
    
    # Signal emitted when search is triggered
    search_requested = pyqtSignal(str, dict)  # (query, options)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Find Packet")
        self.setMinimumWidth(450)
        self.setModal(False)  # Allow interaction with main window
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Search input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Find:"))
        
        self.search_input = QLineEdit()
        self.search_input.setFont(QFont("Consolas", 10))
        self.search_input.setPlaceholderText("Enter search term...")
        self.search_input.returnPressed.connect(self.find_next)
        input_layout.addWidget(self.search_input)
        
        layout.addLayout(input_layout)
        
        # Search type
        type_group = QGroupBox("Search in")
        type_layout = QHBoxLayout(type_group)
        
        self.search_display = QRadioButton("Packet list")
        self.search_display.setChecked(True)
        type_layout.addWidget(self.search_display)
        
        self.search_details = QRadioButton("Packet details")
        type_layout.addWidget(self.search_details)
        
        self.search_bytes = QRadioButton("Packet bytes")
        type_layout.addWidget(self.search_bytes)
        
        layout.addWidget(type_group)
        
        # Search mode
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Search as:"))
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["String", "Hex", "Regex"])
        mode_layout.addWidget(self.mode_combo)
        mode_layout.addStretch()
        
        layout.addLayout(mode_layout)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.case_sensitive = QCheckBox("Case sensitive")
        options_layout.addWidget(self.case_sensitive)
        
        self.wrap_around = QCheckBox("Wrap around")
        self.wrap_around.setChecked(True)
        options_layout.addWidget(self.wrap_around)
        
        options_layout.addStretch()
        layout.addLayout(options_layout)
        
        # Direction
        dir_layout = QHBoxLayout()
        
        self.dir_up = QRadioButton("Up")
        dir_layout.addWidget(self.dir_up)
        
        self.dir_down = QRadioButton("Down")
        self.dir_down.setChecked(True)
        dir_layout.addWidget(self.dir_down)
        
        dir_layout.addStretch()
        layout.addLayout(dir_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.find_btn = QPushButton("Find Next")
        self.find_btn.setDefault(True)
        self.find_btn.clicked.connect(self.find_next)
        button_layout.addWidget(self.find_btn)
        
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        
        # Status
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #666;")
        layout.addWidget(self.status_label)
    
    def find_next(self):
        """Trigger search with current options."""
        query = self.search_input.text()
        if not query:
            self.status_label.setText("Please enter a search term")
            return
        
        options = {
            'mode': self.mode_combo.currentText().lower(),
            'case_sensitive': self.case_sensitive.isChecked(),
            'wrap_around': self.wrap_around.isChecked(),
            'direction': 'up' if self.dir_up.isChecked() else 'down',
            'search_in': 'display' if self.search_display.isChecked() else 
                         'details' if self.search_details.isChecked() else 'bytes'
        }
        
        # Validate hex input
        if options['mode'] == 'hex':
            try:
                # Remove spaces and validate hex
                hex_str = query.replace(' ', '').replace(':', '')
                bytes.fromhex(hex_str)
            except ValueError:
                self.status_label.setText("Invalid hex string")
                return
        
        # Validate regex
        if options['mode'] == 'regex':
            try:
                re.compile(query)
            except re.error as e:
                self.status_label.setText(f"Invalid regex: {e}")
                return
        
        self.search_requested.emit(query, options)
    
    def set_status(self, message, is_error=False):
        """Set status message."""
        color = "#c00" if is_error else "#666"
        self.status_label.setStyleSheet(f"color: {color};")
        self.status_label.setText(message)
    
    def get_search_query(self):
        """Get current search query."""
        return self.search_input.text()
