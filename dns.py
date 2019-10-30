# encoding=utf8
import socket
import time
import select
import argparse

class ReqInfo:
    bits = ''
    Qname = ''
    Qtype = ''
    Qclass = ''
    next = 0
    msg = ''
    addr = ''


class DNSRelay:
    data = []  # local Address - IP pairs

    def __init__(self, args):
        self.args = args  # Command line args
        self.dnsServerIp = args.dnsServerIp  # remote DNS IP
        self.LoadDB(args.dbFile)
        self.sockRecv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockRecv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sockRecv.bind(('0.0.0.0', 53))  # listen all IP at port 53

    def LoadDB(self, file):
        with open(file) as input:
            self.data = [tuple(line.strip().split(' '))
                         for line in input.readlines() if line != "\n"]
        # Debug info
        if self.args.d or self.args.dd:
            self.printTime(5)

    def handleRequest(self, msg, addr):  #
        req = ReqInfo()
        req.bits = self.Byte2Word(msg[2])
        req.QName, req.next = self.getQName(msg)
        req.Qtype = self.Byte2Word(msg[req.next]) + self.Byte2Word(msg[req.next + 1])
        req.Qclass = self.Byte2Word(msg[req.next + 2]) + self.Byte2Word(msg[req.next + 3])
        req.msg = msg
        req.addr = addr

        self.printReqInfo(req)

        if req.bits[0] == '0' and req.bits[1:5] == '0000' and req.Qtype == '0000000000000001' and req.Qclass == '0000000000000001':  # QTYPE=A,QCLASS=IN
            for (ip, domain) in self.data:
                if domain == req.QName:
                    response = self.createResponse(msg, ip)
                    self.sockRecv.sendto(response, addr)
                    # Level 2 Debug info
                    if self.args.dd:
                        self.printTime(1)
                    break
            else:
                if self.args.dd:
                    self.printTime(2)
                # Forward request to remote server
                self.dnsForward(msg, addr)

        else:  # Unsupported request, send to remote server
            # Level 2 Debug info
            if self.args.dd:
                self.printTime(3)
            self.dnsForward(msg, addr)

    def createResponse(self, msg, ip): # Create reply msg
        response = msg[:2]  # ID
        if ip == '0.0.0.0':  # Domain dose not exist
            response += b'\x81\x83'  # RCODE:3 (error)
            response += b'\x00\x01'  # QDCOUNT
            response += b'\x00\x00'  # ANCOUNT
            response += b'\x00\x00'  # NSCOUNT
            response += b'\x00\x00'  # ARCOUNT
            response += msg[12:]
        else:
            response += b'\x81\x80'  # ROCDE:0
            response += b'\x00\x01'  # QDCOUNT
            response += b'\x00\x01'  # ANCOUNT
            response += b'\x00\x00'  # NSCOUNT
            response += b'\x00\x00'  # ARCOUNT
            response += msg[12:]
            response += b'\xC0\x0C'  # Pointer
            response += b'\x00\x01'  # TYPE:A
            response += b'\x00\x01'  # CLASS:IN(1)
            response += b'\x00\x00\x00\xA8'  # TTL:168
            response += b'\x00\x04'  # RDLENGTH:4
            ip = ip.split('.')
            for i in range(4):
                response += int(ip[i]).to_bytes(1, 'big')
        return response

    def dnsForward(self, msg, addr):

        dnsAddr = (self.dnsServerIp, 53)
        msgRecv = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg, dnsAddr)  # Send request to remote server
        ready = select.select([sock], [], [], 5)  # 5000ms timeout
        if ready[0]:
            msgRecv, addrRecv = sock.recvfrom(1024)
        sock.close()

        # Level 2 Debug info
        if msgRecv is not None and self.args.dd:
            self.printTime(6)
            self.sockRecv.sendto(msgRecv, addr)  # send received msg to originator
        elif msgRecv is None and self.args.dd:
            self.printTime(7)



        # Level 2 Debug info
        if self.args.dd:
            self.printTime(4)

    def Byte2Word(self, byte):
        bit = bin(byte)[2:]
        bit = '0' * (8 - len(bit)) + bit
        return bit

    def getQName(self, msg):
        QName = ''
        i = 12
        while msg[i] != 0:
            for j in range(1, msg[i] + 1):
                QName += chr(msg[i + j])
            QName += '.'
            i = i + msg[i] + 1  # Next field
        return QName[:len(QName) - 1], i + 1  # remove last one.

    def run(self):
        while True:
            msg, addr = self.sockRecv.recvfrom(2048)
            self.handleRequest(msg, addr)

    def printReqInfo(self,req):
        if self.args.d:
            self.printTime(0)
            print("QName:" + str(req.QName)," Host:"+str(req.addr))
        if self.args.dd:
            self.printTime(0)
            print("Receive From:" + str(req.addr))
            print("                      Request:" + str(req.msg))
            print("                      QName:" + str(req.QName))
            print("                      ID:" + str(self.Byte2Word(req.msg[0]) + self.Byte2Word(req.msg[1])),
                  "QR:" + str(req.bits[0]),
                  "OPCODE:" + str(req.bits[1:5]),
                  "QTYPE:" + str(req.Qtype),
                  "QCLASS:" + str(req.Qclass))

    def printTime(self,case):
        print(time.strftime("[%Y-%m-%d %H:%M:%S]", time.localtime()), end=' ')
        if case == 1:
            print("IP is in local DB, response sent")
        if case == 2:
            print("IP is not in local DB, relaying the request")
        if case == 3:
            print("Unsupported operation, relaying the request")
        if case == 4:
            print("Response sent")
        if case == 5:
            print("Local DB loaded")
        if case == 6:
            print("Receive from remote server")
        if case == 7:
            print("Failed to get response from remote server")


def main():
    parse = argparse.ArgumentParser(description="This is a DNS relay.")  # 命令行参数
    parse.add_argument('-d', action="store_true", default=False, help="Debug level 1")
    parse.add_argument('-dd', action="store_true", default=False, help="Debug level 2")
    parse.add_argument(dest='dnsServerIp', action="store", nargs='?',default="10.3.9.4", help="DNS server ipaddr")
    parse.add_argument(dest='dbFile', action="store", nargs='?',default="./dnsrelay.txt", help="DB filename")
    args = parse.parse_args()
    print("NameServer:", args.dnsServerIp)
    print("DB file:", args.dbFile)
    print("Debug level:", 2 if args.dd else (1 if args.d else 0))
    dns = DNSRelay(args)
    dns.run()

if __name__ == '__main__':
    main()