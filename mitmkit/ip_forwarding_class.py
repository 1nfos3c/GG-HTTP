# This class can enable packet forwarding.
# It should be made cross platform.
import platform
import subprocess
import os
import logging

class PacketForwarding():

    def __init__(self, *args):
        self.operating_system = platform.system()
        self.print_name = 'IP forwarder'
        self.std_out = ''
        self.logger = args[0]
        self.DEVNUL = open(os.devnull, 'w')
        self.printOS('os')

    def forwardPacket(self):
        self.printOS('forward')
        if(self.operating_system == 'Darwin'):
            #os.system("sudo sysctl -w net.inet.ip.forwarding=1")
            p = subprocess.Popen(['sudo sysctl -w net.inet.ip.forwarding=1'], shell=True, stdout=subprocess.PIPE)
            while p.poll() is None:
                l = p.stdout.readline()
                self.std_out = l
                self.printOS('output')
            # p2 can be used to route packets trough SSLStrip to be able to read them in plaintext :)
            # p2 = subprocess.Popen(['echo "rdr pass inet proto tcp from any to any port 80 -> 127.0.0.1 port 1337 " | sudo pfctl -ef -'], shell=True, stdout=self.DEVNUL, stderr=self.DEVNUL)
            self.printOS('iptable+')
            #this is pre yosemite:
                #os.system("sudo sysctl -w net.inet.ip.fw.enable=1")
        elif(self.operating_system == 'Linux'):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def restoreSettings(self):
        self.printOS('restore')
        if(self.operating_system == 'Darwin'):
            p = subprocess.Popen(['sudo sysctl -w net.inet.ip.forwarding=0'], shell=True, stdout=subprocess.PIPE)
            while p.poll() is None:
                l = p.stdout.readline()
                self.std_out = l
                self.printOS('output')
            p2 = subprocess.Popen(['sudo pfctl -F all -f /etc/pf.conf'], shell=True, stdout=self.DEVNUL, stderr=self.DEVNUL)
            self.printOS('iptable-')
        elif(self.operating_system == 'Linux'):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    def printOS(self, task):
        if (task == 'forward'):
            self.logger.info("[+] " + self.print_name +"  -> \tEnabling IP forwarding.")
        elif (task == 'restore'):
            self.logger.info("[+] " + self.print_name + "  -> \tRestoring IP forwarding settings.")
        elif (task == 'iptable+'):
            #self.logger.info("[+] " + self.print_name + "  -> \tForwarding all traffic on port 80 to port 1337 for SSLStrip.")
            doSomething = 0
        elif (task == 'iptable-'):
            self.logger.info("[-] " + self.print_name + "  -> \tRemoving the previously created port forwarding rules.")
        elif (task == 'output'):
            line = self.std_out.decode('utf-8')
            if not line == "":
                self.logger.info("[+] " + self.print_name + "  -> \t" + line[:-1])
        elif (task == 'os'):
            log = "[+] " + self.print_name + "  -> \tThis OS: " + self.operating_system
            self.logger.info(log)
