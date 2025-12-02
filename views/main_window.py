# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import QMainWindow
from ui_pcapqt import Ui_PcapQt
from models.packet_table_model import PacketTableModel
from models.packet_detail_model import PacketDetailModel
from threads.sniffer_thread import SnifferThread
from utils.packet_parser import PacketParser


class PcapQt(QMainWindow):

    def __init__(self):
        super().__init__()
        self.ui = Ui_PcapQt()
        self.ui.setupUi(self)

        self.packet_model = PacketTableModel()
        self.detail_model = PacketDetailModel()

        self.ui.packageTableView.setModel(self.packet_model)
        self.ui.detailedPackageTableView.setModel(self.detail_model)

        self.ui.packageTableView.horizontalHeader().setStretchLastSection(True)
        self.ui.packageTableView.setSelectionBehavior(self.ui.packageTableView.SelectRows)
        self.ui.packageTableView.setSelectionMode(self.ui.packageTableView.SingleSelection)
        self.ui.packageTableView.setAlternatingRowColors(True)

        self.ui.detailedPackageTableView.horizontalHeader().setStretchLastSection(True)
        self.ui.detailedPackageTableView.verticalHeader().setVisible(False)
        self.ui.detailedPackageTableView.setAlternatingRowColors(True)

        self.sniffer = SnifferThread()
        self.sniffer.packet_captured.connect(self.on_packet_captured)

        self.raw_packets = []
        self.current_packet_index = -1

        self.ui.startCapture.toggled.connect(self.toggle_capture)
        self.ui.restartButton.clicked.connect(self.restart_capture)
        self.ui.packageTableView.selectionModel().currentRowChanged.connect(self.on_packet_selected)
        self.ui.previousPakageButton.clicked.connect(self.go_to_previous)
        self.ui.nextPakageButton.clicked.connect(self.go_to_next)
        self.ui.firstPakageButton.clicked.connect(self.go_to_first)
        self.ui.lastPakageButton.clicked.connect(self.go_to_last)

    def toggle_capture(self, checked):
        if checked:
            self.sniffer.start()
        else:
            self.sniffer.stop()

    def restart_capture(self):
        if self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.wait()

        self.packet_model.clear()
        self.detail_model.clear()
        self.raw_packets.clear()
        self.current_packet_index = -1

        if self.ui.startCapture.isChecked():
            self.ui.startCapture.setChecked(False)

    def on_packet_captured(self, packet, packet_info):
        self.raw_packets.append(packet)

        packet_data = [
            packet_info['no'],
            f"{packet_info['time']:.6f}",
            packet_info['src'],
            packet_info['dst'],
            packet_info['protocol'],
            packet_info['length'],
            packet_info['info']
        ]

        self.packet_model.add_packet(packet_data)

        last_row = self.packet_model.rowCount() - 1
        self.ui.packageTableView.scrollTo(self.packet_model.index(last_row, 0))

    def on_packet_selected(self, current, previous):
        if not current.isValid():
            return

        row = current.row()
        self.current_packet_index = row

        if row < len(self.raw_packets):
            packet = self.raw_packets[row]
            self.display_packet_details(packet)

    def display_packet_details(self, packet):
        details = PacketParser.get_packet_details(packet, self.current_packet_index)
        self.detail_model.set_details(details)
        self.ui.detailedPackageTableView.resizeColumnsToContents()

    def go_to_previous(self):
        if self.current_packet_index > 0:
            new_index = self.current_packet_index - 1
            self.ui.packageTableView.selectRow(new_index)

    def go_to_next(self):
        if self.current_packet_index < len(self.raw_packets) - 1:
            new_index = self.current_packet_index + 1
            self.ui.packageTableView.selectRow(new_index)

    def go_to_first(self):
        if len(self.raw_packets) > 0:
            self.ui.packageTableView.selectRow(0)

    def go_to_last(self):
        if len(self.raw_packets) > 0:
            last_row = len(self.raw_packets) - 1
            self.ui.packageTableView.selectRow(last_row)

    def closeEvent(self, event):
        if self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.wait()
        event.accept()