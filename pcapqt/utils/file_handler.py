# -*- coding: utf-8 -*-
"""
File handler for PCAP file operations.
Supports opening, saving, and exporting packet captures.
"""

from scapy.all import rdpcap, wrpcap
from datetime import datetime
import csv
import os


class FileHandler:
    """Handle PCAP file operations."""
    
    SUPPORTED_EXTENSIONS = ['.pcap', '.pcapng', '.cap']
    
    @staticmethod
    def open_pcap(filepath):
        """
        Open a PCAP/PCAPNG file and return packets.
        
        Args:
            filepath: Path to the PCAP file
            
        Returns:
            tuple: (packets_list, error_message)
                   packets_list is list of Scapy packets or None on error
                   error_message is None on success or error string
        """
        if not os.path.exists(filepath):
            return None, f"File not found: {filepath}"
        
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in FileHandler.SUPPORTED_EXTENSIONS:
            return None, f"Unsupported file format: {ext}"
        
        try:
            packets = rdpcap(filepath)
            return list(packets), None
        except Exception as e:
            return None, f"Error reading file: {str(e)}"
    
    @staticmethod
    def save_pcap(packets, filepath):
        """
        Save packets to a PCAP file.
        
        Args:
            packets: List of Scapy packets
            filepath: Destination file path
            
        Returns:
            tuple: (success, error_message)
        """
        if not packets:
            return False, "No packets to save"
        
        # Ensure .pcap extension
        if not filepath.lower().endswith(('.pcap', '.pcapng')):
            filepath += '.pcap'
        
        try:
            wrpcap(filepath, packets)
            return True, None
        except Exception as e:
            return False, f"Error saving file: {str(e)}"
    
    @staticmethod
    def export_csv(packet_data, filepath, headers=None):
        """
        Export packet list to CSV file.
        
        Args:
            packet_data: List of packet data rows (list of lists)
            filepath: Destination file path
            headers: Optional column headers
            
        Returns:
            tuple: (success, error_message)
        """
        if not packet_data:
            return False, "No data to export"
        
        if not filepath.lower().endswith('.csv'):
            filepath += '.csv'
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if headers:
                    writer.writerow(headers)
                writer.writerows(packet_data)
            return True, None
        except Exception as e:
            return False, f"Error exporting CSV: {str(e)}"
    
    @staticmethod
    def export_text(packet_data, filepath, headers=None):
        """
        Export packet list to plain text file.
        
        Args:
            packet_data: List of packet data rows
            filepath: Destination file path
            headers: Optional column headers
            
        Returns:
            tuple: (success, error_message)
        """
        if not packet_data:
            return False, "No data to export"
        
        if not filepath.lower().endswith('.txt'):
            filepath += '.txt'
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # Write header
                f.write(f"PcapQt Export - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                if headers:
                    f.write("\t".join(str(h) for h in headers) + "\n")
                    f.write("-" * 80 + "\n")
                
                for row in packet_data:
                    f.write("\t".join(str(cell) for cell in row) + "\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Total packets: {len(packet_data)}\n")
            return True, None
        except Exception as e:
            return False, f"Error exporting text: {str(e)}"
    
    @staticmethod
    def export_packet_details(packets, filepath, parser_func):
        """
        Export detailed packet information to text file.
        
        Args:
            packets: List of raw Scapy packets
            filepath: Destination file path
            parser_func: Function to get packet details (returns list of [key, value])
            
        Returns:
            tuple: (success, error_message)
        """
        if not packets:
            return False, "No packets to export"
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"PcapQt Detailed Export - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, packet in enumerate(packets):
                    f.write(f"Packet #{i + 1}\n")
                    f.write("-" * 40 + "\n")
                    
                    try:
                        details = parser_func(packet, i)
                        for key, value in details:
                            if key.startswith('==='):
                                f.write(f"\n{key}\n")
                            else:
                                f.write(f"  {key}: {value}\n")
                    except Exception as e:
                        f.write(f"  Error parsing packet: {e}\n")
                    
                    f.write("\n")
                
                f.write("=" * 80 + "\n")
                f.write(f"Total packets: {len(packets)}\n")
            return True, None
        except Exception as e:
            return False, f"Error exporting details: {str(e)}"
    
    @staticmethod
    def get_file_info(filepath):
        """
        Get information about a PCAP file without fully loading it.
        
        Args:
            filepath: Path to the PCAP file
            
        Returns:
            dict with file information or None on error
        """
        if not os.path.exists(filepath):
            return None
        
        try:
            stat = os.stat(filepath)
            return {
                'path': filepath,
                'filename': os.path.basename(filepath),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'extension': os.path.splitext(filepath)[1].lower()
            }
        except Exception:
            return None
