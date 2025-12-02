import sys
from PyQt5.QtWidgets import QApplication
from views.main_window import PcapQt

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PcapQt()
    window.show()
    sys.exit(app.exec_())
