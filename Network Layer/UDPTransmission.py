  
import sys
import socket
import struct
import re
class UDPPacket(object):
    def __init__(self, src_port,dest_port,length, checksum, payload):
        self.src_port = src_port
        self.dest_port = dest_port
        self.length = length
        self.checksum = checksum
        self.payload = payload
        self.totalSize =  8 + len(payload)

    def get_bytes(self):
        return struct.pack("!HHHH"+str(len(self.payload)) +"s",int(self.src_port)&0xffff,int(self.dest_port)&0xffff,int(self.totalSize)&0xffff,int(self.checksum)&0xffff,self.payload)
    
class IPPacket(object):
    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload
    def get_bytes(self):
        #version ihl service totalLength 
        # That's a byte literal (~byte array)
        # size in bits
        # 4         4       8            16     |   first line
        #version , IHL , serviceType , totalLength
        #   16              3       13          | second line
        #identification , flags, fragmentOffset [flags editied don't fragment]
        #   8           8           16          | third line
        #timeToLive ,  protocol, headerCheckSum  [ ttl 64 ,protocol edited [17 udp]] ‭1074855936‬ if ttl==0 1114112
        #   32                                  | fourth line
        #sourceAddr
        #   32                                   | fifth line
        #destinationAddr = dest_addr
        #  24  [8 padding]                      | sixth line
        #options,   # no need to handle options
        # the rest                              |seventh line                              
        return struct.pack("!BBHIIII"+str(len(self.payload)) +"s",int(((4<<4)|5)&0xff),int(0&0xff),int((20 + len(self.payload))&0xffff),16384,1074855936,int(self.source_address),int(self.destination_address),self.payload)
    

def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.
def get_application_layer_packet(src_port,dest_port,message) -> UDPPacket:
    checksum = 0
    return UDPPacket(src_port,dest_port,len(message),checksum,bytes(message, 'utf-8'))
    
def get_uintger_addr(addr:str):
    matches = re.findall(r"^(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})$", addr)
    if not matches:
        print("Bad IPADDRESS")
        return None
    return int(matches[0][0])<<24 | int(matches[0][1])<<16 | int(matches[0][2])<<8 | int(matches[0][3])

def get_network_layer_packet(udp_pack:UDPPacket,src_addr,dest_addr):
    # gets raw bytes of an IPv4 packet

    data = udp_pack.get_bytes()

    return IPPacket(17, 5, get_uintger_addr(src_addr), get_uintger_addr(dest_addr),data)
  
def main():
    dest_addr = get_arg(1, '127.0.0.1')
    dest_port = int(get_arg(2,44444))
    message = get_arg(3,'hi\n')
    hacker = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_RAW)
    src_port = 44000
    src_addr = '127.0.0.1'
    udp = get_application_layer_packet(src_port,dest_port,message)
    ip = get_network_layer_packet(udp,src_addr,dest_addr)
    hacker.sendto(ip.get_bytes(),(dest_addr,dest_port))
     


if __name__ == "__main__":
    main()