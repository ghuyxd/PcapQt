# -*- coding: utf-8 -*-
"""
Hex dump widget for displaying raw packet bytes.
Shows offset, hex values, and ASCII representation.
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel, QHBoxLayout
from PyQt5.QtGui import QFont, QTextCharFormat, QColor, QTextCursor
from PyQt5.QtCore import Qt


class HexDumpWidget(QWidget):
    """Widget for displaying hex dump of packet data."""
    
    BYTES_PER_LINE = 16
    
    # Colors for highlighting
    OFFSET_COLOR = QColor(100, 100, 100)   # Gray
    HEX_COLOR = QColor(0, 0, 0)             # Black
    ASCII_COLOR = QColor(0, 100, 0)         # Dark green
    HIGHLIGHT_BG = QColor(255, 255, 0)      # Yellow
    NON_PRINTABLE_COLOR = QColor(150, 150, 150)  # Light gray
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_data = None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel("Hex Dump")
        header_label.setStyleSheet("font-weight: bold; color: #333;")
        header_layout.addWidget(header_label)
        
        self.info_label = QLabel("")
        self.info_label.setStyleSheet("color: #666;")
        header_layout.addWidget(self.info_label)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Hex display
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 9))
        self.hex_view.setLineWrapMode(QTextEdit.NoWrap)
        self.hex_view.setStyleSheet("""
            QTextEdit {
                background-color: #fafafa;
                border: 1px solid #ddd;
                selection-background-color: #0078d4;
                selection-color: white;
            }
        """)
        layout.addWidget(self.hex_view)
    
    def set_data(self, data):
        """
        Set raw packet data to display.
        
        Args:
            data: bytes object to display
        """
        self.current_data = data
        self.hex_view.clear()
        
        if not data:
            self.info_label.setText("")
            return
        
        self.info_label.setText(f"({len(data)} bytes)")
        
        cursor = self.hex_view.textCursor()
        
        # Format definitions
        offset_fmt = QTextCharFormat()
        offset_fmt.setForeground(self.OFFSET_COLOR)
        
        hex_fmt = QTextCharFormat()
        hex_fmt.setForeground(self.HEX_COLOR)
        
        ascii_fmt = QTextCharFormat()
        ascii_fmt.setForeground(self.ASCII_COLOR)
        
        nonprint_fmt = QTextCharFormat()
        nonprint_fmt.setForeground(self.NON_PRINTABLE_COLOR)
        
        # Build hex dump
        for offset in range(0, len(data), self.BYTES_PER_LINE):
            chunk = data[offset:offset + self.BYTES_PER_LINE]
            
            # Offset column
            cursor.setCharFormat(offset_fmt)
            cursor.insertText(f"{offset:04x}  ")
            
            # Hex columns
            hex_parts = []
            for i, byte in enumerate(chunk):
                hex_parts.append(f"{byte:02x}")
                if i == 7:
                    hex_parts.append("")  # Extra space in middle
            
            # Pad if less than 16 bytes
            while len(hex_parts) < 17:
                hex_parts.append("  ")
            
            cursor.setCharFormat(hex_fmt)
            cursor.insertText(" ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[9:17]) + "  ")
            
            # ASCII column
            for byte in chunk:
                if 32 <= byte < 127:
                    cursor.setCharFormat(ascii_fmt)
                    cursor.insertText(chr(byte))
                else:
                    cursor.setCharFormat(nonprint_fmt)
                    cursor.insertText(".")
            
            cursor.insertText("\n")
        
        self.hex_view.setTextCursor(cursor)
        self.hex_view.moveCursor(QTextCursor.Start)
    
    def highlight_bytes(self, start, length):
        """
        Highlight a range of bytes in the hex dump.
        
        Args:
            start: Starting byte offset
            length: Number of bytes to highlight
        """
        if not self.current_data or start < 0 or length <= 0:
            return
        
        # Calculate line and column positions
        # This is complex due to formatting, simplified version
        # TODO: Implement proper byte-to-position mapping
        pass
    
    def clear(self):
        """Clear the hex dump display."""
        self.current_data = None
        self.hex_view.clear()
        self.info_label.setText("")
    
    def get_selected_bytes(self):
        """
        Get the bytes that are currently selected.
        
        Returns:
            bytes object or None
        """
        # TODO: Implement selection-to-bytes mapping
        return None
