from socket import *
import array
import struct
import time
import sys

# TCP packet information
ackNum = 0
mss = 576

# Window of packets
window = []
# Class for TCP packet
# Modelled off Nick Kramoff's article on Medium, which was adapted from scapy
class tcpPacket:
    def __init__(self, srcHost: str, srcPort: int, dstHost: str, dstPort: int, ackNum: int, data: bytes, flags = 0):
        self.srcHost = srcHost
        self.srcPort = srcPort
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.ackNum = ackNum
        self.data = data
        self.flags = flags
    def build(self):
        packet = struct.pack(
            '!HHIIBBHHH', # tells struct the type of the variables to follow
            self.srcPort, 
            self.dstPort,
            0, # sequence number
            self.ackNum, # acknowledgement number
            5 << 4, # header length and unused segment
            self.flags, # 8 flags
            0, # window size, (not provided in command line arguments!)
            0, # checksum
            0) # urgent data pointer
        packet = packet[:16] + struct.pack('H', checksum(packet)) + packet[18:]
        return packet

# Checksum function same as in sender.py
def checksum(packet: bytes) -> int:
    if (len(packet) % 2 != 0):
        packet += b'\0'
    res = sum(array.array("H", packet)) # sum of 16 bit words in the packet
    res = (res >> 16) + (res & 0xFFFF)
    res += res >> 16
    return (~res) & 0xFFFF

def main():
    global ackNum # Make local variables global
    global prevAckNum
    global window

    # Open specified file
    fileName = sys.argv[1]    
    storeData = open(fileName, 'wb')
    
    # Receiving data
    destPort = sys.argv[2]
    recvSocket = socket(AF_INET, SOCK_DGRAM) # UDP
    recvSocket.bind(('', int(destPort)))

    # Sending data
    ackName = sys.argv[3]
    ackPort = sys.argv[4]
  
    while True:
        # +24: 20 bytes for TCP header and 4 for length of byte data
        message, clientAddr = recvSocket.recvfrom(mss + 24)

        # Check for corrupt packets
        if (checksum(message) != 0):
            packet = tcpPacket('localhost', int(destPort), ackName, int(ackPort),
            ackNum, b'', 0b00010000)
            recvSocket.sendto(packet.build(), (ackName, int(ackPort)))
            print("Received corrupt packet")
            continue

        # Check for FIN
        if (struct.unpack('!B', message[13:14])[0] % 2 == 1):
            # Send ACK for FIN
            packet = tcpPacket('localhost', int(destPort), ackName, int(ackPort), ackNum, b'', 0b00010000)
            recvSocket.sendto(packet.build(), (ackName, int(ackPort)))
            
            # Send corresponding FIN
            packet = tcpPacket('localhost', int(destPort), ackName, int(ackPort), ackNum, b'', 0b00010001)
            recvSocket.sendto(packet.build(), (ackName, int(ackPort)))
            
            # Close
            break

        # Check for out of order packets
        if (struct.unpack('!I', message[4:8])[0] != ackNum):
            # If lower than current desired acknowledgement number, don't buffer
            if (struct.unpack('!I', message[4:8])[0] < ackNum):
                continue
            # Otherwise, buffer
            toAppend = struct.unpack('!I', message[4:8])[0] # record seq num
            print("Received out of order packet, buffered")
            if (len(window) == 0):
                window.append(message)
            else:
                # Append this packet to window (in increasing order with respect
                # to acknowledgement number)
                for i in range(len(window)):
                    check = struct.unpack('!I', window[len(window) - i - 1][4:8])[0]
                    if (toAppend == check):
                        break
                    if (check < toAppend): 
                        window.insert(len(window) - i, message)
                        break
                for data in window:
                    print(struct.unpack('!I', data[4:8])[0])
            # Sending duplicate ACK
            packet = tcpPacket('localhost', int(destPort), ackName, int(ackPort),
            ackNum, b'', 0b00010000)
            recvSocket.sendto(packet.build(), (ackName, int(ackPort)))

            continue
            
        # If not out of order and corrupt, begin writing
        print("Packet accepted")
        message = message[24:]
        storeData.write(message)
        ackNum += len(message)

        # Then check if there is anything in the window to write
        if (len(window) > 0):
            i = 0
            while (i < len(window)):
                if (ackNum == struct.unpack('!I', window[i][4:8])[0]):
                    window[i] = window[i][24:]
                    storeData.write(window[i])
                    ackNum += len(window[i]) # increment ackNum to account for
                    i = i + 1
                else:    
                    break
            # Remove packets from window that have been read
            if (i == len(window)):
                window = []
            else:
                window = window[i:]

        # Send acknowledgement
        packet = tcpPacket('localhost', int(destPort), ackName, int(ackPort),
        ackNum, b'', 0b00010000)
        recvSocket.sendto(packet.build(), (ackName, int(ackPort)))
if __name__ == "__main__":
    main()
