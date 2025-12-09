# -*- coding: utf-8 -*-
"""
Security Alerts Dialog for displaying detected threats.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QComboBox, QGroupBox, QHeaderView, QTextEdit,
    QSplitter, QWidget, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont

from ..utils.security_analyzer import (
    SecurityAlert, ThreatType, ThreatSeverity, get_security_analyzer
)


class SecurityAlertsDialog(QDialog):
    """Dialog for displaying security alerts."""
    
    alert_added = pyqtSignal(object)  # SecurityAlert
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Security Alerts")
        self.setMinimumSize(900, 600)
        self.analyzer = get_security_analyzer()
        
        self.setup_ui()
        self.load_alerts()
        
        # Note: Callback registration removed - it was being called from sniffer thread
        # which caused crashes when updating UI. Dialog now refreshes on explicit action.
    
    def setup_ui(self):
        """Setup the dialog UI."""
        layout = QVBoxLayout(self)
        
        # Header with stats
        header = self._create_header()
        layout.addWidget(header)
        
        # Filter bar
        filter_bar = self._create_filter_bar()
        layout.addWidget(filter_bar)
        
        # Splitter for table and details
        splitter = QSplitter(Qt.Vertical)
        
        # Alerts table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "ID", "Time", "Severity", "Type", "Source", "Description"
        ])
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.table)
        
        # Details panel
        details_widget = self._create_details_panel()
        splitter.addWidget(details_widget)
        
        splitter.setSizes([400, 200])
        layout.addWidget(splitter)
        
        # Button bar
        button_bar = self._create_button_bar()
        layout.addWidget(button_bar)
    
    def _create_header(self):
        """Create header with statistics."""
        group = QGroupBox("Security Status")
        layout = QHBoxLayout(group)
        
        self.total_label = QLabel("Total Alerts: 0")
        self.critical_label = QLabel("Critical: 0")
        self.critical_label.setStyleSheet("color: red; font-weight: bold;")
        self.high_label = QLabel("High: 0")
        self.high_label.setStyleSheet("color: orange; font-weight: bold;")
        self.medium_label = QLabel("Medium: 0")
        self.low_label = QLabel("Low: 0")
        
        layout.addWidget(self.total_label)
        layout.addWidget(self.critical_label)
        layout.addWidget(self.high_label)
        layout.addWidget(self.medium_label)
        layout.addWidget(self.low_label)
        layout.addStretch()
        
        return group
    
    def _create_filter_bar(self):
        """Create filter controls."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        layout.addWidget(QLabel("Filter by Type:"))
        self.type_filter = QComboBox()
        self.type_filter.addItem("All Types", None)
        for threat_type in ThreatType:
            self.type_filter.addItem(threat_type.value, threat_type)
        self.type_filter.currentIndexChanged.connect(self.load_alerts)
        layout.addWidget(self.type_filter)
        
        layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All Severities", None)
        for severity in ThreatSeverity:
            self.severity_filter.addItem(severity.value, severity)
        self.severity_filter.currentIndexChanged.connect(self.load_alerts)
        layout.addWidget(self.severity_filter)
        
        layout.addStretch()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_alerts)
        layout.addWidget(refresh_btn)
        
        return widget
    
    def _create_details_panel(self):
        """Create details panel."""
        group = QGroupBox("Alert Details")
        layout = QVBoxLayout(group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.details_text)
        
        return group
    
    def _create_button_bar(self):
        """Create button bar."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        clear_btn = QPushButton("Clear All Alerts")
        clear_btn.clicked.connect(self._clear_alerts)
        layout.addWidget(clear_btn)
        
        export_btn = QPushButton("Export to CSV")
        export_btn.clicked.connect(self._export_alerts)
        layout.addWidget(export_btn)
        
        layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        
        return widget
    
    def load_alerts(self):
        """Load alerts into table."""
        # Get filter values
        type_filter = self.type_filter.currentData()
        severity_filter = self.severity_filter.currentData()
        
        # Get alerts
        alerts = self.analyzer.get_alerts(
            threat_type=type_filter,
            severity=severity_filter,
            limit=500
        )
        
        # Update table
        self.table.setRowCount(len(alerts))
        
        severity_counts = {s: 0 for s in ThreatSeverity}
        
        for row, alert in enumerate(reversed(alerts)):  # Newest first
            # ID
            self.table.setItem(row, 0, QTableWidgetItem(str(alert.id)))
            
            # Time
            time_str = alert.timestamp.strftime("%H:%M:%S")
            self.table.setItem(row, 1, QTableWidgetItem(time_str))
            
            # Severity with color
            severity_item = QTableWidgetItem(alert.severity.value)
            severity_item.setBackground(self._get_severity_color(alert.severity))
            self.table.setItem(row, 2, severity_item)
            
            # Type
            self.table.setItem(row, 3, QTableWidgetItem(alert.threat_type.value))
            
            # Source
            source = alert.source_ip
            if alert.target_ip:
                source += f" → {alert.target_ip}"
            self.table.setItem(row, 4, QTableWidgetItem(source))
            
            # Description
            self.table.setItem(row, 5, QTableWidgetItem(alert.description))
            
            severity_counts[alert.severity] += 1
        
        # Update stats
        self.total_label.setText(f"Total Alerts: {len(alerts)}")
        self.critical_label.setText(f"Critical: {severity_counts[ThreatSeverity.CRITICAL]}")
        self.high_label.setText(f"High: {severity_counts[ThreatSeverity.HIGH]}")
        self.medium_label.setText(f"Medium: {severity_counts[ThreatSeverity.MEDIUM]}")
        self.low_label.setText(f"Low: {severity_counts[ThreatSeverity.LOW]}")
    
    def _get_severity_color(self, severity: ThreatSeverity) -> QColor:
        """Get background color for severity level."""
        colors = {
            ThreatSeverity.CRITICAL: QColor(255, 100, 100),  # Red
            ThreatSeverity.HIGH: QColor(255, 180, 100),      # Orange
            ThreatSeverity.MEDIUM: QColor(255, 255, 150),    # Yellow
            ThreatSeverity.LOW: QColor(200, 255, 200),       # Green
        }
        return colors.get(severity, QColor(255, 255, 255))
    
    def _on_selection_changed(self):
        """Handle selection change in table."""
        selected = self.table.selectedItems()
        if not selected:
            self.details_text.clear()
            return
        
        row = selected[0].row()
        
        try:
            # Get alert details
            type_filter = self.type_filter.currentData()
            severity_filter = self.severity_filter.currentData()
            alerts = self.analyzer.get_alerts(
                threat_type=type_filter,
                severity=severity_filter,
                limit=500
            )
            
            alerts_reversed = list(reversed(alerts))
            if row < len(alerts_reversed):
                alert = alerts_reversed[row]
                
                # Format details
                details = f"""Alert ID: {alert.id}
Time: {alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
Type: {alert.threat_type.value}
Severity: {alert.severity.value}

Source IP: {alert.source_ip}
Target IP: {alert.target_ip or 'N/A'}

Description:
{alert.description}

Details:
"""
                for key, value in alert.details.items():
                    details += f"  {key}: {value}\n"
                
                self.details_text.setText(details)
        except (IndexError, AttributeError, RuntimeError):
            self.details_text.clear()
    
    def _on_new_alert(self, alert: SecurityAlert):
        """Handle new alert from analyzer."""
        # Reload if dialog is visible
        if self.isVisible():
            self.load_alerts()
    
    def _clear_alerts(self):
        """Clear all alerts."""
        reply = QMessageBox.question(
            self, "Clear Alerts",
            "Are you sure you want to clear all security alerts?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.analyzer.clear_alerts()
            self.load_alerts()
    
    def _export_alerts(self):
        """Export alerts to CSV file."""
        from PyQt5.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts", "security_alerts.csv",
            "CSV Files (*.csv)"
        )
        if not filename:
            return
        
        try:
            alerts = self.analyzer.get_alerts(limit=10000)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ID,Time,Severity,Type,Source,Target,Description\n")
                for alert in alerts:
                    f.write(f"{alert.id},")
                    f.write(f"{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')},")
                    f.write(f"{alert.severity.value},")
                    f.write(f"{alert.threat_type.value},")
                    f.write(f"{alert.source_ip},")
                    f.write(f"{alert.target_ip or ''},")
                    f.write(f"\"{alert.description}\"\n")
            
            QMessageBox.information(self, "Export Complete",
                                    f"Exported {len(alerts)} alerts to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
    
    def closeEvent(self, event):
        """Handle dialog close."""
        # Note: Callback cleanup removed - no longer registering callbacks
        super().closeEvent(event)
