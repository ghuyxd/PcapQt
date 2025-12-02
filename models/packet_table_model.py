from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex
from PyQt5.QtGui import QColor


class PacketTableModel(QAbstractTableModel):

    def __init__(self):
        super().__init__()
        self.packets = []
        self.headers = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']

    def rowCount(self, parent=QModelIndex()):
        return len(self.packets)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        packet_data = self.packets[index.row()]

        if role == Qt.DisplayRole:
            return packet_data[index.column()]
        elif role == Qt.BackgroundRole:
            protocol = packet_data[4]
            if protocol == 'TCP':
                return QColor(231, 230, 255)
            elif protocol == 'UDP':
                return QColor(218, 238, 255)
            elif protocol == 'ARP':
                return QColor(250, 240, 215)
            elif protocol == 'ICMP':
                return QColor(252, 224, 255)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def add_packet(self, packet_data):
        row = len(self.packets)
        self.beginInsertRows(QModelIndex(), row, row)
        self.packets.append(packet_data)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self.packets.clear()
        self.endResetModel()
