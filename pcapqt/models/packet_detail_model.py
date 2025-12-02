from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex
from PyQt5.QtGui import QColor


class PacketDetailModel(QAbstractTableModel):

    def __init__(self):
        super().__init__()
        self.details = []

    def rowCount(self, parent=QModelIndex()):
        return len(self.details)

    def columnCount(self, parent=QModelIndex()):
        return 2

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        if role == Qt.DisplayRole:
            return self.details[index.row()][index.column()]
        elif role == Qt.BackgroundRole:
            field_name = self.details[index.row()][0]
            if field_name.startswith('==='):
                return QColor(220, 220, 220)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return ['Field', 'Value'][section]
        return None

    def set_details(self, details):
        self.beginResetModel()
        self.details = details
        self.endResetModel()

    def clear(self):
        self.beginResetModel()
        self.details.clear()
        self.endResetModel()
