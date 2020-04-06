
import sys
import os
import enum
import socket
import _thread

cached_sites = {}#public var to hold cached websites

class HttpRequestInfo(object):
    """
    Represents a HTTP request information
    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.
    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.
    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.
    requested_host: the requested website, the remote website
    we want to visit.
    requested_port: port of the webserver we want to visit.
    requested_path: path of the requested resource, without
    including the website name.
    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list,
                 http_ver:str,
                 has_header_error:bool):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        self.http_ver = http_ver
        self.has_header_error = has_header_error
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:
        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n
        (just join the already existing fields by \r\n)
        """
        out = self.method + " " + self.requested_path + " " + self.http_ver + "\r\n"
        for i in range(len(self.headers)):
            out = out + self.headers[i][0]+": "+self.headers[i][1]+"\r\n"
        out = out + "\r\n"
        return out



    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        """ Same as above """
        out = str(self.code) + " " + self.message + "\r\n"
        out = out + "\r\n"
        return out

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1

def to_byte_array(http_string):
        """
        Converts String to Byte Array
        """
        return bytes(http_string, "UTF-8")

def entry_point(proxy_port_number):
    server_socket = setup_sockets(proxy_port_number)
    server_socket.listen(24)#any number >10 
    while True:
        connection, client_address = server_socket.accept()
        _thread.start_new_thread(handleClient, (connection,client_address,))
    return None


def setup_sockets(proxy_port_number):
    print("Starting HTTP proxy on port:", proxy_port_number)
    server_socket = socket.socket(socket.AF_INET,  socket.SOCK_STREAM) #create TCP Socket
    server_address = ("127.0.0.1", int(proxy_port_number))
    server_socket.bind(server_address)
    return server_socket


def handleClient(connection,client_address):
     data = b''
     try:
        while True:
            chunk = connection.recv(32)
            data = data + chunk
            if data.decode("utf-8")[-4:] == "\r\n\r\n":
                break
     finally:
        httpresponse = http_request_pipeline(client_address,data.decode("utf8"))
        if isinstance(httpresponse,HttpErrorResponse):
            connection.send(to_byte_array(httpresponse.to_http_string()))
        else:
            msg = get_message(httpresponse)
            connection.send(msg)
        connection.close()

    
def get_message(httpresponse):
    sendmsg = httpresponse.to_http_string()
    if sendmsg in cached_sites: #if site cached return it
        return cached_sites[sendmsg]
    retrieve_socket = socket.socket()
    retrieve_socket.connect((httpresponse.requested_host, httpresponse.requested_port)) 
    retrieve_socket.send(to_byte_array(sendmsg))
    data = b''
    try:
        while True:
            chunk = retrieve_socket.recv(128)
            data = data + chunk
            if not chunk:
                break
    finally:
        retrieve_socket.close()
    cached_sites[sendmsg] = data
    return data


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.
    - Parses it
    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Returns a sanitized HttpRequestInfo
    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.
    """
    # Parse HTTP request
    ret = parse_http_request(source_addr, http_raw_data)
    validity = check_http_request_validity(ret)
    if validity == HttpRequestState.GOOD:
        return ret
    elif validity == HttpRequestState.INVALID_INPUT:
        ret = HttpErrorResponse(400,"Bad Request")
        return ret
    elif validity == HttpRequestState.NOT_SUPPORTED:
        ret = HttpErrorResponse(501,"Not Implemented")
        return ret

def parse_http_request(source_addr, http_raw_data):
    method,urlpath,httpver,headers,hasErrors = get_basic_http_info(http_raw_data)
    hosturl,port,path = getValidDestinationInfo(urlpath,headers)
    ret = HttpRequestInfo(source_addr, method, hosturl, int(port), path ,headers,httpver,hasErrors)
    return ret



def check_http_request_validity(parsedRequest:HttpRequestInfo) -> HttpRequestState:
    """
    Checks if an HTTP request is valid
    returns:
    One of values in HttpRequestState
    """
    #CHECK HTTPVER? 
    hosturlheader = ''
    if parsedRequest.has_header_error:
        return HttpRequestState.INVALID_INPUT
    for i in range(len(parsedRequest.headers)):
        if parsedRequest.headers[i][0].lower() == "host":
            hosturlheader= getHostPort(parsedRequest.headers[i][1])[0]
            break
    if parsedRequest.requested_host == '' and hosturlheader == '':
         return HttpRequestState.INVALID_INPUT
    if parsedRequest.requested_host != '' and hosturlheader != '' and parsedRequest.requested_host != hosturlheader:
         return HttpRequestState.INVALID_INPUT
    if parsedRequest.method.lower() == "get":
            return HttpRequestState.GOOD
    elif parsedRequest.method.lower() == "put":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "head":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "post":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "delete":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "link":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "unlink":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "patch":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "connect":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "options":
            return HttpRequestState.NOT_SUPPORTED
    elif parsedRequest.method.lower() == "trace":
            return HttpRequestState.NOT_SUPPORTED        
    return HttpRequestState.INVALID_INPUT

def get_basic_http_info(http_raw_data):
    requestLines = http_raw_data.split("\r\n")
    method,urlpath,httpver = parseRequestLine(requestLines[0])
    iterator = 1
    headers = []
    while iterator < len(requestLines):
        if requestLines[iterator] == "":
            iterator = iterator + 1
            continue
        import re
        matches = re.findall(r"^(\S+): (\S+)$", requestLines[iterator])
        if not matches:
            return [method,urlpath,httpver,[],True]
        headers.append([matches[0][0],matches[0][1]])
        iterator = iterator + 1
    return [method,urlpath,httpver,headers,False]

def parseRequestLine(line):
    import re
    matches = re.findall(r"^(\S+) (\S+) (HTTP\/\d.\d)$", line)
    method = ''
    urlpath = ''
    httpver = ''
    if matches:
        method = matches[0][0]
        urlpath = matches[0][1]
        httpver = matches[0][2]
    return [method,urlpath,httpver]

def getValidDestinationInfo(urlpath,headers):
    hosturl,port,path = getHostPort(urlpath)
    if hosturl == '':
         hosturlheader = ''
         portheader = ''
         pathheader = ''
         for i in range(len(headers)):
                if headers[i][0].lower() == "host":
                   hosturlheader,portheader,notused = getHostPort(headers[i][1])
                   return [hosturlheader,portheader,path]
    else:
        if port == "80":
               headers.append(["Host",hosturl])
        else:
            headers.append(["Host",hosturl+":"+port])
    return [hosturl,port,path]

def getHostPort(url):
    import re
    matches = re.findall(r"^(?:https?:)?(?:\/\/)?(?:[^@\n]+@)?((?:www\.)?[^:\/\n]+)?(?::(\d+)?)?(\/.*)?$", url)
    if not matches:
        return ['','','']
    host = matches[0][0]
    port = matches[0][1]
    if port == '':
        port = "80"
    path = matches[0][2]
    if path == '':
        path = "/"
    return [host,port,path]

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

def main():
    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()