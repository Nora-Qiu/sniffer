
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtGui import QFont, QPalette, QColor
from funcs import *
from scapy.all import *
import netifaces as nif
import psutil
from threading import Thread,Lock
import time
import datetime
import socket
from input_dialogue import *

class Ui_capturing_window():
    def __init__(self,nic, addr, ftext,start_window):
        #print("Ui_capturing_window")
        self.nic = nic
        self.chosen_mac = None
        self.chosen_ip = None
        if ':' in addr:
            self.chosen_mac = addr
        else:self.chosen_ip = addr
        self.capturing_status = True
        self.ip_protocols = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
        if ftext=="Sniffer Filter":
            self.ftext = ""
        else:
            self.ftext = ftext
        self.window_to_reshow = start_window
        self.pckts = []


    def setupUi(self, MainWindow):

        self.my_window = MainWindow
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        QtWidgets.QToolTip.setFont(QFont('Helvetica', 10))
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor('#D2DAFF'))  # 设置背景颜色
        MainWindow.setPalette(palette)

        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")

        self.button_start = QtWidgets.QPushButton(self.centralwidget)
        self.button_start.setObjectName("button_start")
        self.button_start.setFixedSize(46, 46)
        self.button_start.setStyleSheet(''' QPushButton {border-radius: 23px;border: 2px solid white; background-color: #86C8BC; color: white;font-size: 16px;}
         QPushButton:hover {background-color: white; color: #86C8BC; }''')
        self.button_start.clicked.connect(self.start_c)
        self.button_start.setGeometry(QtCore.QRect(300, 520, 50, 50))

        self.button_stop = QtWidgets.QPushButton(self.centralwidget)
        self.button_stop .setObjectName("button_start")
        self.button_stop .setFixedSize(46, 46)
        self.button_stop .setStyleSheet(''' QPushButton {border-radius: 23px; border: 2px solid white;background-color: #FD8A8A; color: white;font-size: 16px;} 
        QPushButton:hover {background-color: white; color: #FD8A8A; }''')
        self.button_stop .clicked.connect(self.stop_c)
        self.button_stop .setGeometry(QtCore.QRect(450, 520, 50, 50))

        self.Search = QtWidgets.QLineEdit(self.centralwidget)
        self.Search.setObjectName("Search")
        self.Search.setGeometry(QtCore.QRect(50, 10, 600, 30))
        self.pnum = QtWidgets.QLineEdit(self.centralwidget)
        self.pnum.setObjectName("packets")
        #self.verticalLayout.addWidget(self.Search)
        self.pnum.setReadOnly(True)
        self.pnum.setGeometry(QtCore.QRect(630, 535, 120, 20))
        self.pnum.setStyleSheet("QLineEdit {background-color: #D2DAFF;color: black;font-size: 10px;}")
        self.pnum.setText("packets : 0")
        self.Searchbutton = QtWidgets.QToolButton(self.centralwidget)
        self.Searchbutton.setObjectName("Searchbutton")
        self.Searchbutton.setGeometry(QtCore.QRect(680, 10, 100, 30))
        self.Searchbutton.setStyleSheet("""
                    QToolButton {
                        background-color: #B1B2FF;
                        color: white;
                        border: 2px solid white;
                        border-radius: 10px;
                        padding: 5px;
                        font-size: 12px;
                    }

                    QToolButton:hover {
                        background-color: white;
                        color: #B1B2FF;
                    }
                """)

        #self.verticalLayout.addWidget(self.Searchbutton)
        self.Packets_table = QtWidgets.QTableWidget(self.centralwidget)
        self.Packets_table.setObjectName("Packets")
        self.Packets_table.setColumnCount(7)
        self.Packets_table.setRowCount(0)
        self.Packets_table.setColumnWidth(0,150) ###########################
        self.Packets_table.itemSelectionChanged.connect(self.selected_change)
        self.Packets_table.setStyleSheet("QTableWidget { background-color: #D2DAFF; font-size: 10px; }"
                                  #"QTableWidget::item { background-color: #EEF1FF; color: #000000; }"
                                  "QTableWidget::item:selected { background-color: #B1B2FF color: #ffffff; }")

        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(6, item)
        #self.verticalLayout.addWidget(self.Packets_table)
        header = self.Packets_table.horizontalHeader()
        # 设置背景颜色
        font = QFont('Helvetica', 12)
        font.setBold(True)
        header.setStyleSheet("color: black;")
        header.setFont(font)


        self.Packets_table.setGeometry(QtCore.QRect(50, 50, 700, 200))
        # self.line_2 = QtWidgets.QFrame(self.centralwidget)
        # self.line_2.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        # self.line_2.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        # self.line_2.setObjectName("line_2")
        # self.verticalLayout.addWidget(self.line_2)

        self.pack_details = QtWidgets.QTextBrowser(self.centralwidget)
        self.pack_details.setObjectName("pack_hex")
        #self.verticalLayout.addWidget(self.pack_details)
        self.pack_details.setGeometry(QtCore.QRect(50, 260,340, 250))
        self.pack_raw = QtWidgets.QTextBrowser(self.centralwidget)
        self.pack_raw.setObjectName("pack_hex")
        #self.verticalLayout.addWidget(self.pack_raw)
        self.pack_raw.setGeometry(QtCore.QRect(410, 260, 340, 250))
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 676, 21))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuCapture = QtWidgets.QMenu(self.menubar)
        self.menuCapture.setObjectName("menuCapture")
        #self.menuHelp = QtWidgets.QMenu(self.menubar)
        #self.menuHelp.setObjectName("menuHelp")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.actionOpen = QtGui.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionOpen.triggered.connect(self.load_c)


        self.actionSave = QtGui.QAction(MainWindow)
        self.actionSave.setObjectName("actionSave")
        self.actionSave.triggered.connect(self.save_c)

        self.actionBack = QtGui.QAction(MainWindow)
        self.actionBack.setObjectName("actionBack")
        self.actionBack.triggered.connect(self.back_c)


        self.actionClear = QtGui.QAction(MainWindow)
        self.actionClear.setObjectName("actionClear")
        self.actionClear.triggered.connect(self.clear_c)


        self.actionStart = QtGui.QAction(MainWindow)
        self.actionStart.setObjectName("actionStart")
        self.actionStart.triggered.connect(self.start_c)


        self.actionStop = QtGui.QAction(MainWindow)
        self.actionStop.setObjectName("actionStop")
        self.actionStop.triggered.connect(self.stop_c)


        self.menuFile.addAction(self.actionOpen)
        self.menuFile.addAction(self.actionSave)
        self.menuFile.addAction(self.actionBack)


        self.menuCapture.addAction(self.actionStart)
        self.menuCapture.addAction(self.actionStop)
        self.menuCapture.addAction(self.actionClear)

        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuCapture.menuAction())
        #self.menubar.addAction(self.menuHelp.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.Searchbutton.clicked.connect(self.filter_c)



    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", f"capturing {self.nic}"))
        self.Search.setText(_translate("MainWindow", "Filter"))
        self.Searchbutton.setText(_translate("MainWindow", "Search"))

        item = self.Packets_table.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Time"))
        item = self.Packets_table.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "IP_Source"))
        item = self.Packets_table.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "IP_Destination"))
        item = self.Packets_table.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Port_Source"))
        item = self.Packets_table.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Port_Destination"))
        item = self.Packets_table.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "Protocol"))
        item = self.Packets_table.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "Length"))
        #item = self.Packets_table.horizontalHeaderItem(5)
        #item.setText(_translate("MainWindow", "Info"))

        self.button_start.setText(_translate("MainWindow", "Start"))
        self.button_stop.setText(_translate("MainWindow", "Stop"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuCapture.setTitle(_translate("MainWindow", "Run"))
        #self.menuHelp.setTitle(_translate("MainWindow", "Help"))
        self.actionOpen.setText(_translate("MainWindow", "Open"))
        self.actionSave.setText(_translate("MainWindow", "Save"))
        self.actionBack.setText(_translate("MainWindow", "Back"))
        self.actionClear.setText(_translate("MainWindow", "Clear"))
        self.actionStart.setText(_translate("MainWindow", "Start"))
        self.actionStop.setText(_translate("MainWindow", "Stop"))


    def reshow(self):
        self.window_to_reshow.show()


    def back_c(self):
        self.reshow()
        self.my_window.close()


    def pro(self,pkt):
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
            return "HTTP"

        elif pkt.haslayer(TCP) and pkt[TCP].dport == 443:
            return "HTTPS"

        elif pkt.haslayer(DNS):
            return "DNS"

        elif pkt.haslayer(TCP) and pkt[TCP].dport == 21:
            return "FTP"

        elif pkt.haslayer(TCP) and pkt[TCP].dport == 25:
            return "SMTP"

        elif pkt.haslayer(TCP) and pkt[TCP].dport == 22:
            return "SSH"

        else:
            return ""

    def filter_c(self):
        f = self.Search.text()
        self.clear_c()

        if f=='' or f=="Filter":
            pass
        else:
            rules = {}
            if 'and' in f:
                for i in f.replace(' ', '').split('and'):
                    rules[i.split('=')[0]] = i.split('=')[1]
            else:
                rules[f.split('=')[0]] = f.split('=')[1]
            print(rules)
            for p in self.pckts:
                try:
                    src_port = ''
                    dst_port = ''
                    serch_res = {}
                    if IPv6 in p:

                        if proto in [6, 17]:
                            src_port = p[proto].sport
                            dst_port = p[proto].dport
                        search_res = {'src_ip': p[IPv6].src, 'dst_ip': p[IPv6].dst, 'src_port': src_port,
                                      'dst_port': dst_port, 'pro': str(p[IPv6].nh),
                                      'alp': str(p[IPv6].nh)}
                        search_res['ip_type'] = str(6)
                    else:
                        if p.haslayer(TCP):
                            src_port = p[TCP].sport
                            dst_port = p[TCP].dport
                        if p.haslayer(UDP):
                            src_port = p[UDP].sport
                            dst_port = p[UDP].dport
                        search_res = {'src_ip': p[IP].src, 'dst_ip': p[IP].dst, 'src_port': str(src_port),
                                      'dst_port': str(dst_port), 'pro': str(self.ip_protocols[int(p[IP].proto)]),
                                      'alp': self.pro(p)}
                        search_res['ip_type'] = str(4)

                    print(search_res)
                    t=0
                    for i in rules:
                        if rules[i]!=search_res[i]:
                            t+=1
                    if t==0:
                        rowPosition = self.Packets_table.rowCount()
                        self.Packets_table.insertRow(rowPosition)
                        self.Packets_table.setItem(rowPosition, 0, QtWidgets.QTableWidgetItem(
                            str(datetime.datetime.fromtimestamp(p.time))))
                        self.Packets_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(p[IP].src))
                        self.Packets_table.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(p[IP].dst))
                        self.Packets_table.setItem(rowPosition, 3, QtWidgets.QTableWidgetItem(str(src_port)))
                        self.Packets_table.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(dst_port)))
                        self.Packets_table.setItem(rowPosition, 5,
                                                   QtWidgets.QTableWidgetItem(self.ip_protocols[int(p[IP].proto)]))
                        self.Packets_table.setItem(rowPosition, 6, QtWidgets.QTableWidgetItem(str(p[IP].len)))

                except:
                    pass

    def start_c(self):
        print(self.chosen_ip)
        if self.chosen_ip is None:
            self.back_c()
        self.capturing_status = True
        self.threaded_sniff_target()

    def stop_c(self):
        self.capturing_status = False
        time.sleep(0.8)
        self.pnum.setText(f"packets: {len(self.pckts)}")

    def sniffed_packet(self,p):
        src_port=''
        dst_port=''
        if IPv6 in p:
            rowPosition = self.Packets_table.rowCount()
            src_addr = p[IPv6].src
            dst_addr = p[IPv6].dst
            proto = p[IPv6].nh
            if proto in [6, 17]:
                src_port = p[proto].sport
                dst_port = p[proto].dport
            self.Packets_table.insertRow(rowPosition)
            # self.lock.acquire()
            self.pckts.append(p)
            # self.Packets_table.setItem(rowPosition, 0, QtWidgets.QTableWidgetItem(str(len(self.pckts))))
            self.Packets_table.setItem(rowPosition, 0,
                                       QtWidgets.QTableWidgetItem(str(datetime.datetime.fromtimestamp(p.time))))
            self.Packets_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(str(src_addr)))
            self.Packets_table.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(str(dst_addr)))
            self.Packets_table.setItem(rowPosition, 3, QtWidgets.QTableWidgetItem(str(src_port)))
            self.Packets_table.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(dst_port)))
            self.Packets_table.setItem(rowPosition, 5, QtWidgets.QTableWidgetItem(proto))
            self.Packets_table.setItem(rowPosition, 6, QtWidgets.QTableWidgetItem(str(p[IPv6].len)))


        else:
            try:
                #if self.chosen_ip in [p[IP].src, p[IP].dst]:
                rowPosition = self.Packets_table.rowCount()
                if p.haslayer(TCP):
                    src_port = p[TCP].sport
                    dst_port = p[TCP].dport
                if p.haslayer(UDP):
                    src_port = p[UDP].sport
                    dst_port = p[UDP].dport
                self.Packets_table.insertRow(rowPosition)
                #self.lock.acquire()
                self.pckts.append(p)
                #self.Packets_table.setItem(rowPosition, 0, QtWidgets.QTableWidgetItem(str(len(self.pckts))))
                self.Packets_table.setItem(rowPosition, 0, QtWidgets.QTableWidgetItem(str(datetime.datetime.fromtimestamp(p.time))))
                self.Packets_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(p[IP].src))
                self.Packets_table.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(p[IP].dst))
                self.Packets_table.setItem(rowPosition, 3, QtWidgets.QTableWidgetItem(str(src_port)))
                self.Packets_table.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(dst_port)))
                self.Packets_table.setItem(rowPosition, 5, QtWidgets.QTableWidgetItem(self.ip_protocols[int(p[IP].proto)]))
                self.Packets_table.setItem(rowPosition, 6, QtWidgets.QTableWidgetItem(str(p[IP].len)))
            except:pass


    def threaded_sniff_target(self):
        t = AsyncSniffer(iface=self.nic,filter=self.ftext,prn=self.sniffed_packet,count=0,stop_filter=lambda p: not self.capturing_status)
        t.start()


    def selected_change(self):
        print(len(self.pckts))
        index = self.Packets_table.currentRow()
        p = self.pckts[index]
        b = p.show
        p.show()
        try:

            e = str(b).index("<Raw")
            hex_dump = my_hexdump2(p)
            self.pack_raw.setText(hex_dump)
            hexdump(p)
            hd2 = my_hexdump2(p)

        except:
            e = -1
            self.pack_raw.setText(" ")

        self.pack_details.setText((("\n" + "-"*150 + "\n").join(str(b)[28: e].split("|"))).replace(" ","\n"))


    def save_c(self):
        try:
            dialouge_box = Dialouge()
            self.file_name = dialouge_box. initUI(save=True)
            wrpcap(self.file_name, self.pckts)
        except:
            self.save_err_msg()


    def load_c(self):
        try:
            dialouge_box = Dialouge()
            self.file_name = dialouge_box.initUI()

            self.pckts = rdpcap(self.file_name)
            self.clear_c()
            for p in self.pckts:
                src_port = ''
                dst_port = ''
                if IPv6 in p:
                    try:
                        rowPosition = self.Packets_table.rowCount()
                        src_addr = p[IPv6].src
                        dst_addr = p[IPv6].dst
                        proto = p[IPv6].nh
                        if proto in [6, 17]:
                            src_port = p[proto].sport
                            dst_port = p[proto].dport
                        self.Packets_table.insertRow(rowPosition)
                        self.Packets_table.setItem(rowPosition, 0,
                                                   QtWidgets.QTableWidgetItem(str(datetime.datetime.fromtimestamp(p.time))))
                        self.Packets_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(str(src_addr)))
                        self.Packets_table.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(str(dst_addr)))
                        self.Packets_table.setItem(rowPosition, 3, QtWidgets.QTableWidgetItem(str(src_port)))
                        self.Packets_table.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(dst_port)))
                        self.Packets_table.setItem(rowPosition, 5, QtWidgets.QTableWidgetItem(proto))
                        self.Packets_table.setItem(rowPosition, 6, QtWidgets.QTableWidgetItem(str(p[IPv6].len)))
                    except:pass

                else:
                    try:
                        # if self.chosen_ip in [p[IP].src, p[IP].dst]:
                        rowPosition = self.Packets_table.rowCount()
                        if p.haslayer(TCP):
                            src_port = p[TCP].sport
                            dst_port = p[TCP].dport
                        if p.haslayer(UDP):
                            src_port = p[UDP].sport
                            dst_port = p[UDP].dport
                        self.Packets_table.insertRow(rowPosition)

                        self.Packets_table.setItem(rowPosition, 0, QtWidgets.QTableWidgetItem(
                            str(datetime.datetime.fromtimestamp(p.time))))
                        self.Packets_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(p[IP].src))
                        self.Packets_table.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(p[IP].dst))
                        self.Packets_table.setItem(rowPosition, 3, QtWidgets.QTableWidgetItem(str(src_port)))
                        self.Packets_table.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(dst_port)))
                        self.Packets_table.setItem(rowPosition, 5,
                                                   QtWidgets.QTableWidgetItem(self.ip_protocols[int(p[IP].proto)]))
                        self.Packets_table.setItem(rowPosition, 6, QtWidgets.QTableWidgetItem(str(p[IP].len)))
                    except:
                        pass

        except:
            #self.load_err_msg()
            pass

    def clear_c(self):
        self.Packets_table.setRowCount(0)
        self.pack_raw.setText("")
        self.pack_details.setText("")


    def save_err_msg(self):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Icon.Critical)
        msg.setWindowTitle("Error Message")
        msg.setText("couldn't save file")
        msg.exec()


    def load_err_msg(self):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Icon.Critical)
        msg.setWindowTitle("Error Message")
        msg.setText("select an existing file to be loaded")
        msg.exec()


