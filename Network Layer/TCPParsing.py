import socket
import binascii
import struct
class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    ipAddr, = struct.unpack("!I",raw_ip_addr)
    return str((ipAddr >> 24))+"." + str(((ipAddr >> 16) &0xff)) + "." + str(((ipAddr >> 8) &0xff)) + "." + str((ipAddr &0xff))

def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array)
    # size in bits  [CAREFUL SOME VALUES HARD CODED IN PARSING HELPER FUNCTIONS]
    # 16           16     | first line
    sourcePort , destinationPort = get_tcp_data_line1(ip_packet_payload)
    #  32                 | second line
    sequenceNumber, = struct.unpack("!I",ip_packet_payload[4:8])
    #  32                 | third line
    ackNumber, = struct.unpack("!I",ip_packet_payload[8:12])
    # 4            12      16   | fourth line
    dataOffset,reserved,window = get_tcp_data_line4(ip_packet_payload)
    #   16          16 | fifth line
    checkSum , urgentPointer = get_tcp_data_line5(ip_packet_payload)
    #  24  [8 padding]                      | sixth line
    #options, = struct.unpack("!I",ip_packet_payload[20:24]) # no need to handle options not needed and we can get the data directly
    # the rest                              |seventh line
    data = ip_packet_payload[dataOffset*4:]
    try:
        decoded = data.decode("utf-8")
        print(decoded)
    except UnicodeDecodeError:
        print("None")

    # print TCP LAYER 
    #print("-"*50)
    #print(sourcePort,destinationPort)
    #print(sequenceNumber)
    #print(ackNumber)
    #print(dataOffset,reserved,window)
    #print(checkSum,urgentPointer)
    ##print(options)
    #print(data) #required
    return TcpPacket(sourcePort, destinationPort, dataOffset, data)

def get_tcp_data_line1(ip_packet: bytes):
    #process the byte array and returns correct valeus for first line
    src_port,dest_port = struct.unpack("!HH",ip_packet[0:4])
    return [src_port,dest_port]
def get_tcp_data_line4(ip_packet: bytes):
      #process the byte array and returns correct valeus for fourth line
    offsetRes,window = struct.unpack("!HH",ip_packet[12:16])
    return [(offsetRes>>12),(offsetRes&0x0fff),window]
def get_tcp_data_line5(ip_packet: bytes):
      #process the byte array and returns correct valeus for fifth line
    check_sum,urgent_ptr = struct.unpack("!HH",ip_packet[16:20])
    return [check_sum,urgent_ptr]

def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array)
    # size in bits  [CAREFUL SOME VALUES HARD CODED IN PARSING HELPER FUNCTIONS]
    # 4         4       8            16     |   first line
    version , IHL , serviceType , totalLength = get_ip_data_line1(ip_packet)
    #   16              3       13          | second line
    identification , flags, fragmentOffset = get_ip_data_line2(ip_packet)
    #   8           8           16          | third line
    timeToLive ,  protocol, headerCheckSum = get_ip_data_line3(ip_packet)
    #   32                                  | fourth line
    sourceAddr = parse_raw_ip_addr(ip_packet[12:16])
    #   32                                   | fifth line
    destinationAddr = parse_raw_ip_addr(ip_packet[16:20])
    #  24  [8 padding]                      | sixth line
    #options, = struct.unpack("!I",ip_packet[20:24])        # no need to handle options not needed and we can get the data directly
    #options = options >> 8
    # the rest                              |seventh line
    data = ip_packet[IHL*4:]

    # print NETWORK LAYER 
    #print("*"*50)
    #print(version,IHL,serviceType,totalLength)
    #print(identification,flags,fragmentOffset)
    #print(timeToLive,protocol,headerCheckSum)
    #print(sourceAddr)
    #print(destinationAddr)
    ##print(options)
    #print(data)
    return IpPacket(protocol, IHL, sourceAddr, destinationAddr,data)

def get_ip_data_line1(ip_packet: bytes):
    #process the byte array and returns correct valeus for first line
    ver_ihl,servtype,totlen = struct.unpack("!BBH",ip_packet[0:4])
    return [(ver_ihl >> 4),(ver_ihl & 0x0f),servtype,totlen]

def get_ip_data_line2(ip_packet: bytes):
    #process the byte array and returns correct valeus for second line
    id,flagFragOff = struct.unpack("!HH",ip_packet[4:8])
    return [id,(flagFragOff >> 13),(flagFragOff & 0x1fff)]
    
def get_ip_data_line3(ip_packet: bytes):
    #process the byte array and returns correct valeus for third line
    return  struct.unpack("!BBH",ip_packet[8:12])
def main():
     TCP = 0x0006
     stealer = socket.socket(socket.AF_INET,socket.SOCK_RAW, TCP)
     iface_name = "lo"
     stealer.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
     while True:
        chunk , addr = stealer.recvfrom(4096)
        #print(binascii.hexlify(chunk)) ##easily view the hex content
        internetLayerData = parse_network_layer_packet(chunk)
        tcpLayerData = parse_application_layer_packet(internetLayerData.payload)




if __name__ == "__main__":
    main()