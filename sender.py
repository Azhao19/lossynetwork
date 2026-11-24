import array
from socket import *
import struct
import select
import time
import sys

# GLOBAL VARIABLES
# functions which modify these variables will have a global declaration at
# execution start

# Window management
mss = 576 # maximum segment size
windSize = int(sys.argv[4]) #
maxPackets = int(sys.argv[4])//576 # maximum size of window array
window = [] # packet buffer
smallestAck = 0 # smallest ACK num in window

# Timing management
factor = float(sys.argv[7]) # for testing purposes
estimatedRTT = 0 # 0 second default
devRTT = 0 # 0 second default
timeout = float(sys.argv[6]) # 1 second default 
measuringRTT = False # checks if measuring RTT
ackToWaitFor = 0 # what ACK will make measuringRTT go from T to F
seqMeasure = 0 # the sequence number of the packed used to measure RTT
tic = 0 # start time for sampleRTT
toc = 0 # end time for sampleRTT
timer = 0 # for timeouts
timerOn = False # checks if clock is active

# Source info
srcPort = 41191
sendSocket = socket(AF_INET, SOCK_DGRAM)
sendSocket.bind(('', srcPort))

# Receiving info
ackPort = sys.argv[5]
ackSocket = socket(AF_INET, SOCK_DGRAM)
ackSocket.bind(('', int(ackPort)))
ackSocket.setblocking(False) # we will periodically check this for ACKs

# sending info
udplAddr = sys.argv[2]
udplPort = sys.argv[3]

# TCP header numbering
ackNum = 0 # of receiver
seqNumNext = 0 # sequence number of next packet to be sent

# FIN management
sentFin = False # tracks if FIN has been sent

# Class for TCP packet
# Modeled off Nick Kramoff's article on Medium, which was adapted from scapy
class tcpPacket:
    def __init__(self, srcHost: str, srcPort: int, dstHost: str, dstPort: int,
    windSize: int, seqNum: int, data: bytes, flags: int = 0):
        self.srcHost = srcHost
        self.srcPort = srcPort
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.windSize = windSize
        self.seqNum = seqNum
        self.ackNum = ackNum
        self.data = data
        self.flags = flags
    def build(self):
        s = self.data
        packet = struct.pack(
            "!HHIIBBHHHI%ds" % len(s), # tells struct the type of the variables to follow
            self.srcPort, 
            self.dstPort,
            self.seqNum, # sequence number
            0, # acknowledgement number
            5 << 4, # header length and unused segment
            self.flags, # 8 flags
            self.windSize, # window size
            0, # checksum
            0, # urgent data pointer
            len(s),
            self.data) # byte data
        packet = packet[:16] + struct.pack('H', checksum(packet)) + packet[18:]
        return packet
def checksum(packet: bytes) -> int:
    if (len(packet) % 2 != 0): # if packet has odd length, pad it
        packet += b'\0'

    # checksum calculation
    res = sum(array.array('H', packet)) 
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

def checkForAcks(ackSocket, fin: int):
    global tic
    global toc
    global seqMeasure
    global window
    global measuringRTT
    global ackToWaitFor
    global estimatedRTT
    global devRTT
    global timeout
    # Read from socket if possible
    readyToRead, readyToWrite, inError = select.select([ackSocket], [], [], 0.0001)
    if (len(readyToRead) == 0):
        return None
    print("Got an ACK!")
    message, addr = ackSocket.recvfrom(20)
    
    # Check for corrupted ACK
    if (checksum(message) != 0):
        return None

    # If FIN is sent, do end routine, else keep updating window
    if (fin == 1):
        last = tcpPacket('localhost', srcPort, udplAddr, int(udplPort), windSize, seqNumNext, b'0', 0b00010001) # send FIN

        # Clean up
        sendSocket.sendto(last.build(), (udplAddr, int(udplPort)))
        sendSocket.close()
        ackSocket.close()
        window = [] 
        timesAcked = []
        
        return None
    else:
        ack = struct.unpack('!I', message[8:12])[0] # get ACK num in packet
        if (ack >= smallestAck):
            # Loop through window to see if we need to process ACK
            i = 0
            while (i < len(window)):
                # In addition to 20 bytes of header we have 4 bytes of integer
                # recording the length of the bytes payload; so, look for an ACK num
                # which is ack - len(window[i]) + 24
                if (ack - len(window[i]) + 24 == struct.unpack('!I', window[i][4:8])[0]):
                    print("Adjusting window buffer")
                    # Slice off packets up to i as per TCP
                    if (i + 1 == len(window)):
                        window = []
                    else:
                        window = window[i+1:]
                i = i + 1
                # Check if this ACK num corresponds to a packet sent to measure RTT
                if (measuringRTT and ack >= ackToWaitFor): # should this be >= or =
                    # We are no longer measuring RTT
                    measuringRTT = False
                    
                    # Record end time
                    toc = time.time() 

                    # Textbook calculations
                    sampleRTT = toc - tic 
                    print("Sample RTT: %f" % sampleRTT)
                    estimatedRTT = 0.875 * estimatedRTT + 0.125 * sampleRTT
                    devRTT = 0.75 * devRTT + 0.25 * abs(sampleRTT - estimatedRTT)
                    timeout = estimatedRTT + 4 * devRTT 
                    print("Timeout value after measuring RTT: %f" % timeout)
                # If nothing in window, ignore timer; else start timer
                if (len(window) == 0):
                    timerOn = False 
                else: 
                    timer = time.time()

def cleanup():
    global tic
    global toc
    global seqMeasure
    global timer
    global timeout
    global sentFin
    global measuringRTT
    while (len(window) > 0):
        # If packets time out here, we only double timeout since there are no
        # more packets we can use to measure the RTT
        if (timerOn and time.time() - timer > timeout):
            if (measuringRTT and seqMeasure == struct.unpack('!I',
            window[0][4:8])[0]):
                measuringRTT = False
            print("Resending %d" % struct.unpack('!I', window[0][4:8])[0])
            sendSocket.sendto(window[0], (udplAddr, int(udplPort)))
            timer = time.time()
            timeout = factor * timeout
            print("New timeout: %f" % timeout)
        # If the window contains only a FIN packet, we want to reach the socket
        # cleanup stage of checkForAcks; we also want the window to be empty
        if (sentFin):
            checkForAcks(ackSocket, 1) # hijack ACK checking to FIN checking
        else: 
            checkForAcks(ackSocket, 0)
    
    # Deallocated resources in above loop, so we are done with clean up
    if (sentFin):
        return None 
    
    # Once the window is clear for the first time, we load it with FIN and begin
    # termination using cleaup() again
    fin = tcpPacket('localhost', srcPort, udplAddr, int(udplPort), windSize, seqNumNext, b'0', 0b00010001)
    sentFin = True
    window.append(fin.build())
    cleanup()

def main():
    global tic
    global toc
    global seqNumNext
    global measuringRTT
    global timerOn
    global timeout
    global ackToWaitFor
    
    # Open the file to read
    fileName = sys.argv[1]
    sendData = open(fileName, 'rb')

    while True:
        # Continuously check for ACKs
        checkForAcks(ackSocket, 0)
        
        # We can always send if the maxPackets size has not yet been reached
        if (len(window) != maxPackets):
            toSend = sendData.read(mss)
            # No data to send means we have reached the end of the file
            if (len(toSend) == 0):
                break
            else: 
                packet = tcpPacket('localhost', srcPort, udplAddr, int(udplPort), windSize, seqNumNext, toSend, 0b00010000)
                window.append(packet.build())# add this packet to the window (needs an ACK)
                if (len(window) == 1):
                    smallestAck = seqNumNext
                sendSocket.sendto(packet.build(), (udplAddr, int(udplPort))) # send
                print("Sending packet %d" % seqNumNext)                
                # Start measuring RTT if not doing so
                if (not measuringRTT): 
                    seqMeasure = seqNumNext # Record the sequence number of
                                            # measuring packet
                    
                    print("Measuring RTT on %d" % (seqNumNext))
                    tic = time.time() # start timer
                    ackToWaitFor = seqNumNext + len(toSend) # ACK packet should have this num
                    measuringRTT = True
                
                # Start main timer if it is off
                if (not timerOn): 
                    timer = time.time()
                    timerOn = True
                seqNumNext += len(toSend) # next sequence number to send
                

        # On timeout, (by default) double timeout interval
        if (timerOn and time.time() - timer > timeout):
            if (measuringRTT and seqMeasure == struct.unpack('!I',
            window[0][4:8])[0]):
                measuringRTT = False
            print("Resending %d" % struct.unpack('!I', window[0][4:8])[0])
            sendSocket.sendto(window[0], (udplAddr, int(udplPort)))
            timer = time.time()
            timeout = factor * timeout
            print("New timeout: %f" % timeout)

    # Loop is done when no packets left to send
    # So it remains to clear out the buffer in window
    cleanup()
if __name__ == "__main__":
    main()
