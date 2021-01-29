from binaryninja.interaction import (
    show_message_box,
    get_int_input,
    get_choice_input
)
from binaryninjaui import (
    DockHandler,
    DockContextHandler,
    getMonospaceFont,
    UIActionHandler
)

from PySide2 import QtCore
from PySide2.QtCore import Qt, QMimeData
from PySide2.QtGui import QBrush, QColor
from PySide2.QtWidgets import (
    QApplication,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QMenu
)

import pyqtgraph as pg

class RegisterView(QWidget, DockContextHandler):

    def __init__(self, parent, name, data):
        print(" ---------- Initializing visualization view ----------")

        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        
        self.parent = parent

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self._layout = QVBoxLayout()

        pg.plot([5, 6, 7, 8, 9])

        print(" ---------- Initialized visualization view  ---------- ")

class PlotView(QWidget, DockContextHandler):

    def __init__(self, parent, name, data):
        print(" ---------- Initializing visualization view ----------")

        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        
        self.parent = parent

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.layout = QVBoxLayout()

        plt1 = pg.PlotWidget(name="Plot 1", clickable=False)
        
        plt1.setLabel("left", "Value", units="V")

        #plt = QLineSeries()

        self.layout.addWidget(plt1)
        #self.layout.addWidget(plt2)

        plt1.plot([5, 6, 7, 8], [9, 10, 11, 12])
        #plt2.plot([5, 6, 7, 8], [9, 10, 11, 12])

        self.setLayout(self.layout)

        #pg.plot([5, 6, 7, 8, 9])

        print(" ---------- Initialized visualization view  ---------- ")


def get_window(name, parent, data):
    window = PlotView(parent, name, data)
    window.setWindowTitle("Here is a new title")
    window.setEnabled(False)

    return window

dock_handler = DockHandler.getActiveDockHandler()
dock_handler.addDockWidget(
    "SENinja Registers",
    get_window,
    Qt.RightDockWidgetArea,
    Qt.Vertical,
    False
)

print("Done running test plugin")
