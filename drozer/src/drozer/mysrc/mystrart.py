# __author__ = 'fenglin'
#-*- coding: utf-8 -*-
import logging
import shlex
import sys
from PyQt4 import QtGui
from PyQt4 import QtCore
from mwr.common import logger
from pydiesel.api.protobuf_pb2 import Message
from drozer.console import Console
from drozer.console.session import Session
from qttest1 import Ui_Dialog
class argument:
        accept_certificate = False
        command = "connect"
        debug = False
        device = None
        file = []
        no_color = False
        onecmd = None
        password = bool(None)
        server= None
        ssl = False


class TestUI(QtGui.QWidget, Ui_Dialog):
    arguments = None
    myconsole = None
    scan_flag = True
    myapp = None
    # myapp = StartMYUi()
    # myapp.show()
    # sys.exit(app.exec_())
    def __init__(self, parent =None):
        logger.setLevel(logging.DEBUG)
        logger.addStreamHandler()
        self.arguments = argument()
        self.myconsole = Console()
        self.app = QtGui.QApplication(sys.argv)
        QtGui.QWidget.__init__(self, parent)
        self.setupUi(self)
        self.retranslateUi(self)
        self.setWindowModality(QtCore.Qt.WindowModal)
        self.show()
        sys.exit(self.app.exec_())


    def start(self):
        if self.scan_flag:
            self.scan_flag = False
            self.lineEdit_5.setText("hello")
            line = "run app.package.attacksurface com.thinksky.itools.markets"
            device, server, response = self.myconsole.get_device_server_response(self.arguments)
            if response.type == Message.SYSTEM_RESPONSE and\
                        response.system_response.status == Message.SystemResponse.SUCCESS:
                session_id = response.system_response.session_id
                try:
                    session = Session(server, session_id, self.arguments)
                    # session.do_run(line)
                    argv = shlex.split(line)
                    module =session.get_module(argv[1:])
                    module.run(argv[2:], self)
                except KeyboardInterrupt:
                    print
                    print "Caught SIGINT, terminating your session."
                finally:
                    session.sqlstdout.closemysql()
                    session.do_exit("")
        else:
            self.progressBar.setProperty("value", 0)

# class A (QtGui.QWidget, TestUI, Ui_Dialog):
#     def __init__(self, parent = None):
#         self.app = QtGui.QApplication(sys.argv)
#         QtGui.QWidget.__init__(self, parent)
#         self.setupUi(self)
#         self.retranslateUi(self)
#         # self.myapp = StartMYUi()
#         self.show()
#         sys.exit(self.app.exec_())
# A()
TestUI()