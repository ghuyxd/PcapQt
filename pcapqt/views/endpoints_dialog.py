# -*- coding: utf-8 -*-
"""
Endpoints dialog.
Shows all unique endpoints with traffic statistics.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QTabWidget, QHeaderView
)
from PyQt5.QtGui import QFont

from ..utils.helpers import create_number_item, create_bytes_item


class EndpointsDialog(QDialog):
    """Dialog for displaying endpoint statistics."""
    
    def __init__(self, ip_endpoints, eth_endpoints, parent=None):
        super().__init__(parent)
        self.ip_endpoints = ip_endpoints
        self.eth_endpoints = eth_endpoints
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Endpoints")
        self.setMinimumSize(700, 450)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Tabs
        self.tabs = QTabWidget()
        
        # IPv4 endpoints
        ipv4_endpoints = [e for e in self.ip_endpoints if e['type'] == 'IPv4']
        if ipv4_endpoints:
            ipv4_widget = self._create_ip_table(ipv4_endpoints)
            self.tabs.addTab(ipv4_widget, f"IPv4 ({len(ipv4_endpoints)})")
        
        # IPv6 endpoints
        ipv6_endpoints = [e for e in self.ip_endpoints if e['type'] == 'IPv6']
        if ipv6_endpoints:
            ipv6_widget = self._create_ip_table(ipv6_endpoints)
            self.tabs.addTab(ipv6_widget, f"IPv6 ({len(ipv6_endpoints)})")
        
        # Ethernet endpoints
        if self.eth_endpoints:
            eth_widget = self._create_eth_table(self.eth_endpoints)
            self.tabs.addTab(eth_widget, f"Ethernet ({len(self.eth_endpoints)})")
        
        layout.addWidget(self.tabs)
        
        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def _create_ip_table(self, endpoints):
        """Create table for IP endpoints."""
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            "Address", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes", "Total Packets"
        ])
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setFont(QFont("Consolas", 9))
        table.setSortingEnabled(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        
        table.setRowCount(len(endpoints))
        for row, endpoint in enumerate(endpoints):
            table.setItem(row, 0, QTableWidgetItem(endpoint['address']))
            table.setItem(row, 1, create_number_item(endpoint['tx_packets']))
            table.setItem(row, 2, create_bytes_item(endpoint['tx_bytes']))
            table.setItem(row, 3, create_number_item(endpoint['rx_packets']))
            table.setItem(row, 4, create_bytes_item(endpoint['rx_bytes']))
            table.setItem(row, 5, create_number_item(endpoint['packets_total']))
        
        return table
    
    def _create_eth_table(self, endpoints):
        """Create table for Ethernet endpoints."""
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["MAC Address", "Packets", "Bytes"])
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setFont(QFont("Consolas", 9))
        table.setSortingEnabled(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        
        table.setRowCount(len(endpoints))
        for row, endpoint in enumerate(endpoints):
            table.setItem(row, 0, QTableWidgetItem(endpoint['address']))
            table.setItem(row, 1, create_number_item(endpoint['packets']))
            table.setItem(row, 2, create_bytes_item(endpoint['bytes']))
        
        return table
