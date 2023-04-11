from PyQt6.QtGui import QFont
from PyQt6 import QtCore, QtGui, QtWidgets
from funcs import *
import capture_window as gui
from PyQt6.QtGui import QPalette, QColor

class Ui_MainWindow(object):

    def setupUi(self, MainWindow):
        self.my_window = MainWindow
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        QtWidgets.QToolTip.setFont(QFont('Helvetica', 10))
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor('#D2DAFF'))  # 设置背景颜色
        MainWindow.setPalette(palette)

        #MainWindow.setWindowTitle('Sniffer_仇渝淇_202228018670015')
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        # self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        # self.gridLayout.setObjectName("gridLayout")
        self.net_interfece = QtWidgets.QListWidget(self.centralwidget)
        self.net_interfece.setObjectName("net_interfece")
        #self.net_interfece.move(400, 100)
        self.net_interfece.setGeometry(QtCore.QRect(200, 50, 400, 400))
        #########################################################################
        self.Filter = QtWidgets.QLineEdit(self.centralwidget)
        self.Filter .setObjectName("Filter")
        # self.verticalLayout.addWidget(self.Search)

        self.Filter .setGeometry(QtCore.QRect(200, 470, 400, 30))


        ############################################################################
       #self.gridLayout.addWidget(self.net_interfece, 0, 0, 1, 1)
        self.Start_capture = QtWidgets.QToolButton(self.centralwidget)
        self.Start_capture.setObjectName("Start_capture")
        #self.gridLayout.addWidget(self.Start_capture, 1, 0, 1, 1)
        self.Start_capture.setGeometry(QtCore.QRect(300, 520, 200, 50))

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 613, 21))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")

        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionOpen = QtGui.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionOpen.triggered.connect(self.load_c)


        self.actionStart = QtGui.QAction(MainWindow)
        self.actionStart.setObjectName("actionStart")
        self.actionStopr = QtGui.QAction(MainWindow)
        self.actionStopr.setObjectName("actionStopr")
        self.actionRestart = QtGui.QAction(MainWindow)
        self.actionRestart.setObjectName("actionRestart")
        self.menuFile.addAction(self.actionOpen)

        self.menubar.addAction(self.menuFile.menuAction())


        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)


        # add event handlers heres
        self.Start_capture.clicked.connect(self.start_capture_btn_clicked)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Sniffer_仇渝淇_202228018670015"))
        __sortingEnabled = self.net_interfece.isSortingEnabled()
        self.net_interfece.setSortingEnabled(False)


        #################################################################
        self.network_interfaces, self.mac_addresses = get_all_interfaces()
        #print(self.network_interfaces)
        for ni in self.network_interfaces:
            item = QtWidgets.QListWidgetItem()
            self.net_interfece.addItem(item)
            item.setText(_translate("MainWindow", ni))
        #################################################################
        self.Filter.setText(_translate("MainWindow", "Sniffer Filter"))
        self.net_interfece.setSortingEnabled(__sortingEnabled)
        self.Start_capture.setText(_translate("MainWindow", "Select Network Interface"))
        self.Start_capture.setStyleSheet("""
            QToolButton {
                background-color: #B1B2FF;
                color: white;
                border: 2px solid white;
                border-radius: 10px;
                padding: 5px;
                font-size: 14px;
            }
            QToolButton:hover {
                background-color: white;
                color: #B1B2FF;
            }
        """)
        self.net_interfece.setStyleSheet("QListWidget { background-color: #AAC4FF; font-size: 12px; }"
                                         "QListWidget::item:selected {background-color: #B1B2FF color: #ffffff; }")

        self.menuFile.setTitle(_translate("MainWindow", "File"))

        self.actionOpen.setText(_translate("MainWindow", "Open"))

        self.actionStart.setText(_translate("MainWindow", "Start"))
        self.actionStopr.setText(_translate("MainWindow", "Stop"))
        self.actionRestart.setText(_translate("MainWindow", "Restart"))



    def start_capture_btn_clicked(self):
        selected_index = self.net_interfece.currentRow()
        print('选择网卡：',self.network_interfaces[selected_index],'地址：',self.mac_addresses[selected_index])
        self.chosen = self.mac_addresses[selected_index]

        self.ftext = self.Filter.text()
        self.newWindow = QtWidgets.QMainWindow()
        self.new_ui = gui.Ui_capturing_window(self.network_interfaces[selected_index],self.chosen, self.ftext, self.my_window)
        self.new_ui.setupUi(self.newWindow)
        self.newWindow.show()
        self.my_window.hide()



    def load_c(self):
        self.newWindow = QtWidgets.QMainWindow()
        self.new_ui = gui.Ui_capturing_window(None, self.my_window)
        self.new_ui.setupUi(self.newWindow)
        self.newWindow.show()
        self.new_ui.load_c()
        self.my_window.hide()


    def load_err_msg(self):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Icon.Critical)
        msg.setWindowTitle("Error Message")
        msg.setText("File not found!")
        msg.exec()






if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())

