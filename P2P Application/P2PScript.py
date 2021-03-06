import sys
import os
import threading
import socket
import time
import uuid
import struct
import datetime

# https://bluesock.org/~willkg/dev/ansi.html
ANSI_RESET = "\u001B[0m"
ANSI_RED = "\u001B[31m"
ANSI_GREEN = "\u001B[32m"
ANSI_YELLOW = "\u001B[33m"
ANSI_BLUE = "\u001B[34m"

_NODE_UUID = str(uuid.uuid4())[:8]


def print_yellow(msg):
    print(f"{ANSI_YELLOW}{msg}{ANSI_RESET}")


def print_blue(msg):
    print(f"{ANSI_BLUE}{msg}{ANSI_RESET}")


def print_red(msg):
    print(f"{ANSI_RED}{msg}{ANSI_RESET}")


def print_green(msg):
    print(f"{ANSI_GREEN}{msg}{ANSI_RESET}")


def get_broadcast_port():
    return 35498


def get_node_uuid():
    return _NODE_UUID


class NeighborInfo(object):
    def __init__(self, delay, broadcast_count, ip=None, tcp_port=None):
        # Ip and port are optional, if you want to store them.
        self.delay = delay
        self.broadcast_count = broadcast_count
        self.ip = ip
        self.tcp_port = tcp_port


############################################
#######  Y  O  U  R     C  O  D  E  ########
############################################


# Don't change any variable's name.
# Use this hashmap to store the information of your neighbor nodes.
neighbor_information = {}
# Leave the server socket as global variable.
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 0))# using 0 as port to let the OS assign random port number
TCPPortNumber = server.getsockname()[1] # get the assigned port number

# Leave broadcaster as a global variable.
broadcaster = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
broadcaster.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT , 1)
broadcaster.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
broadcaster.bind(('0.0.0.0', get_broadcast_port()))
# Setup the UDP socket


def send_broadcast_thread():
    node_uuid = get_node_uuid()
    while True:
        broadcaster.sendto((node_uuid + ' ON ' + str(TCPPortNumber)).encode('utf-8', errors='ignore'), ('255.255.255.255', get_broadcast_port()))
        time.sleep(1)   # Leave as is.
def receive_broadcast_thread():
    """
    Receive broadcasts from other nodes,
    launches a thread to connect to new nodes
    and exchange timestamps.
    """
    import re
    while True:
        data, (ip, port) = broadcaster.recvfrom(4096)
        matches = re.findall(r"^(\w{8}) ON (\d{1,5})$", data.decode("utf-8", errors="ignore"))
        if not matches:#wrong format
            continue
        nodeID = matches[0][0]
        nodeTCPPort = matches[0][1]

        if get_node_uuid() == nodeID:
            continue
        if not nodeID in neighbor_information.keys():
          neighbor_information[nodeID] = NeighborInfo(0, 1, ip,  int(nodeTCPPort))
          exchange_thread = daemon_thread_builder(exchange_timestamps_thread, (nodeID,ip, int(nodeTCPPort)))
          exchange_thread.start()
        else:
          neighbor_information[nodeID].broadcast_count += 1 
          if neighbor_information[nodeID].broadcast_count == 10:
            neighbor_information[nodeID].broadcast_count = 1
            exchange_thread = daemon_thread_builder(exchange_timestamps_thread, (nodeID,ip, int(nodeTCPPort)))
            exchange_thread.start()   
        print_blue(f"RECV: {data} FROM: {ip}:{port}")

def tcp_server_thread():
    """
    Accept connections from other nodes and send them
    this node's timestamp once they connect.
    """
    server.listen(24)#any number >10 
    while True:
        connection, client_addr = server.accept()
        sendTimeStamp(connection)
        connection.close()
       
    


def exchange_timestamps_thread(other_uuid: str, other_ip: str, other_tcp_port: int):
    """
    Open a connection to the other_ip, other_tcp_port
    and do the steps to exchange timestamps.
    Then update the neighbor_info map using other node's UUID.
    """
    #print_yellow(f"ATTEMPTING TO CONNECT TO {other_uuid}")
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
      mySocket.connect((other_ip, other_tcp_port))
      sendTimeStamp(mySocket)
      receivedData = mySocket.recvfrom(4096)
      other_time_stamp, = struct.unpack('!d', receivedData[0])
      mySocket.close()
      delay = datetime.datetime.now(datetime.timezone.utc).timestamp() - other_time_stamp
      neighbor_information[other_uuid].delay = delay
      print_green(delay)
    except ConnectionRefusedError:
      del neighbor_information[other_uuid]
      
     
   

def sendTimeStamp(con):
    timestamp = struct.pack("!d", datetime.datetime.now(datetime.timezone.utc).timestamp())
    con.send(timestamp)


def daemon_thread_builder(target, args=()) -> threading.Thread:
    """
    Use this function to make threads. Leave as is.
    """
    th = threading.Thread(target=target, args=args)
    th.setDaemon(True)
    return th


def entrypoint():
        serverTCPThread = daemon_thread_builder(tcp_server_thread)
        serverTCPThread.start()
        sendingThread = daemon_thread_builder(send_broadcast_thread)
        sendingThread.start()
        recieveThread = daemon_thread_builder(receive_broadcast_thread)
        recieveThread.start()
        serverTCPThread.join()
        sendingThread.join()
        recieveThread.join()
        

############################################
############################################


def main():
    """
    Leave as is.
    """
    try:
      print("*" * 50)
      print_red("To terminate this program use: CTRL+C")
      print_red("If the program blocks/throws, you have to terminate it manually.")
      print_green(f"NODE UUID: {get_node_uuid()}")
      print("*" * 50)
      time.sleep(2)   # Wait a little bit.
      entrypoint()
    except KeyboardInterrupt:
        sys.exit(0)#in case user used CTRL + C to terminate program -> No Traceback errors printed


if __name__ == "__main__":
    main()