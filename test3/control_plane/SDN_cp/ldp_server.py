#!/usr/bin/python

# Mock LDP server for minimum handshake
# Implements both TCP (handshake) and UDP server (Hello)

import threading
import time
import socket
import struct
import pprint
import socketserver
import logging as logger
import sys

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.contrib.ldp import *
from scapy.fields import *

LDP_LENGTH = 4
INTF_IP = sys.argv[1]
LSR_ID = sys.argv[2]
PEER_LSR_ID = sys.argv[3]
MCAST_GRP = '224.0.0.2'
PORT_LDP = 646
MCAST_PORT = 646

class LDPIPv4Transport(Packet):
    oName = "Telemetry Report Header"

    fields_desc = [
        BitField('type', 1025, 16),
        BitField('len', 4, 16),
        IPField('value', "127.0.0.1")
    ]

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if sys.argv[4] in i:
            iface=i
            break;
    if not iface:
        print ("Cannot find "+sys.argv[4]+" interface")
        exit(1)
    return iface


def thread_function(name):
    iface = get_if()
    logger.info({'module': 'server', 'msg': 'Starting'})

    while True:
        time.sleep(5)
        logger.info({'module': 'server', 'msg': 'Sending hello...'})
        pkt = Ether(src= get_if_hwaddr(iface), dst=sys.argv[5])
        pkt = pkt / IP(src=INTF_IP, dst="224.0.0.2", ttl=1) # / TCP(dport=1234, sport=random.randint(49152,65535))
        pkt = pkt / UDP(dport=646, sport=646)
        pkt = pkt / LDP(id=LSR_ID, space=0)
        pkt = pkt / LDPHello(id=0x0, params=[15,0,0], len=20)
        #pkt = pkt / LDPIPv4Transport(type=1025, len=4, value="192.168.2.2")
        pkt = pkt / LDPLabelReqM(u=0, type=0x0401, len=4, id=ip2int(LSR_ID))

        #pkt.show2()
        sendp(pkt, iface=iface, verbose=False)


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    msg_id = 10

    def handle(self):
        close = 0
        logger.info({'module': 'server', 'msg': 'Client connected %s to TCP server' % self.client_address[0]})
        cur_thread = threading.current_thread()
        print("thread %s" % cur_thread.name)

        while not close:
            data = self.request.recv(512)

            if not data:
                # EOF, client closed, just return
                return

            ldp = LDP(data)
            try:
                response = build_answer(ldp, self.msg_id)
            except:
                response = "Bad request"
                logger.exception({'module': 'server', 'msg': 'Problem handling request %s' % self.client_address[0]})

            self.request.sendall(response.build())


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):

    msg_id = 10

    def handle(self):
        logger.info({'module': 'server', 'msg': 'Message received %s by UDP client' % self.client_address[0]})

        port = self.client_address[1]
        socket = self.request[1]

        data = self.request[0].strip()
        ldp = LDP(data)

        cur_thread = threading.current_thread()
        print("thread %s" % cur_thread.name)

        try:
            response = build_answer(ldp, self.msg_id)
            print(response)
            logger.info({'module': 'server', 'msg': 'Building answer ...'})
        except:
            logger.exception({'module': 'server', 'msg': 'Problem handling request %s' % self.client_address[0]})

        socket.sendto(response.build(), (MCAST_GRP, MCAST_PORT))
        #socket.sendto(response.build())

class ThreadedUDPServer(socketserver.ThreadingMixIn,socketserver.UDPServer):
    logger.info({'module': 'server', 'msg': 'Listening in UDP server'})

    def __init__(self, *args):
        super().__init__(*args)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IP,
                               socket.IP_ADD_MEMBERSHIP,
                               socket.inet_aton(MCAST_GRP)+socket.inet_aton(LSR_ID))
        self.socket.bind((MCAST_GRP, MCAST_PORT))


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def recv_all(connection):
    BUFF_SIZE = 512  # 512 KiB
    data = b''
    data = connection.recv(BUFF_SIZE)
    return data


def recvfrom_all(sock):
    BUFF_SIZE = 512  # 512 KiB
    data = b''
    address = ""
    data, address = sock.recvfrom(BUFF_SIZE)
    return data, address


def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1


def last_ldp_layer(packet):
    last_index = len(packet.layers())
    counter = 0
    last_ldp = 0
    while counter < last_index:
        layer = packet.getlayer(counter)
        if layer.name == "LDP":
            last_ldp = counter
        counter += 1
    return last_ldp


def only_message(ldp, iteration):
    if iteration == (len(ldp.layers()) - 1):
        return True
    return False


def only_message_in_ldp_layer(ldp, iteration):
    if ldp_ans[iteration-1].name == "LDP":
        if iteration == (len(ldp.layers()) - 1):
            return True
        elif (iteration+1) < len(ldp.layers()) and ldp[iteration+1].name == "LDP":
            return True;
        else:
            return False
    else:
        return False


def build_answer(ldp, msg_id):
    ldp_ans = None
    create_ldp = False
    i = -1
    for layer in get_packet_layers(ldp):
        i += 1
        if create_ldp:
            if ldp_ans is not None and last_ldp_layer(ldp_ans) == (len(ldp_ans.layers()) - 1):
                ldp_ans = None

            ldp_base = LDP(version=1, id=LSR_ID, space=0)

            if ldp_ans is None:
                ldp_ans = ldp_base
            else:
                ldp_ans = ldp_ans / ldp_base
            create_ldp = False
        if layer.name == "LDP":
            create_ldp = True
            pass
        elif layer.name == "LDPInit":
            ldp_ans = ldp_ans / LDPInit(u=0, type=0x0200, len=22, id=msg_id, params=[180, 0, 0, 0, 0, PEER_LSR_ID, 0])
            msg_id += 1
            ldp_ans = ldp_ans / LDPKeepAlive(u=0, type=0x0201, len=4, id=msg_id)
            msg_id += 1
            ldp_ans[last_ldp_layer(ldp_ans)].len = len(ldp_ans[last_ldp_layer(ldp_ans)]) - 4
        elif layer.name == "LDPKeepAlive":
            if only_message(ldp, i):
                ldp_ans = ldp_ans / LDPKeepAlive(u=0, type=0x0201, len=4, id=msg_id)
                msg_id += 1
            else:
                pass
        elif layer.name == "LDPAddress":
            ldp_ans = ldp_ans / LDPAddress(u=0, type=0x0300, len=14, id=msg_id, address=[LSR_ID])
            msg_id += 1
            ldp_ans[last_ldp_layer(ldp_ans)].len = len(ldp_ans[last_ldp_layer(ldp_ans)]) - 4
        elif layer.name == "LDPHello":
            ldp_ans = ldp_ans / LDPHello(u=0, type=0x0100, len=14, id=0, params=[15, 0, 0])
            ldp_ans = ldp_ans / LDPLabelReqM(u=0, type=0x0401, len=4, id=ip2int(LSR_ID))
            ldp_ans[last_ldp_layer(ldp_ans)].len = len(ldp_ans[last_ldp_layer(ldp_ans)]) - 4

    return ldp_ans


def Listen(type):
    msg_id = 10

    if type == "TCP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    server_address = ('192.168.99.1', 646)
    logger.info({('Listening up on %s port %s' % server_address[0], str(server_address[1]))})

    sock.bind(server_address)

    if type == "TCP":
        sock.listen(1)

    while True:
        data = b''
        connection = None
        client_address = ''

        # Wait for a connection
        logger.info({('Waiting for a connection ...')})

        if type == "TCP":
            connection, client_address = sock.accept()

        try:
            while True:
                if type == "TCP":
                    data = recv_all(connection)
                else:
                    data, client_address = recvfrom_all(sock)

                logger.info({('Connection from %s' % client_address)})

                payload_length = len(data)
                logger.info({('Received some data with %s bytes of length' % payload_length)})

                if data:
                    ldp = LDP(data)  # This msg will hold ldp + ldp_init and other messages
                    logger.info({('%s' % pprint.pprint(ldp))})

                    answer = build_answer(ldp, msg_id)
                    pprint.pprint(answer)

                    logger.info({('Sending data back to the client')})
                    if type == "TCP":
                        connection.sendall(answer)
                    else:
                        sock.sendto(answer, client_address)
                else:
                    logger.info({('no data from %s' % client_address)})
                    break

        finally:
            # Clean up the connection
            connection.close()


def main():

    logger.getLogger().setLevel(logger.INFO)

    server_tcp = ThreadedTCPServer((INTF_IP, PORT_LDP), ThreadedTCPRequestHandler)
    #server_udp = ThreadedUDPServer((LSR_ID, MCAST_PORT), ThreadedUDPRequestHandler)

    server_thread_tcp = threading.Thread(name='TCP Server2', target=server_tcp.serve_forever)
    #server_thread_udp = threading.Thread(name='UDP Multicast Client', target=server_udp.serve_forever)

    ip_tcp, port_tcp = server_tcp.server_address
    #ip_udp, port_udp = server_udp.server_address

    logger.info({'module': 'server', 'msg': 'Listening On %s:%s for TCP' % (ip_tcp, port_tcp)})
    #logger.info({'module': 'server', 'msg': 'Listening On %s:%s for UDP' % (ip_udp, port_udp)})

    x = threading.Thread(target=thread_function, args=(1,))
    x.start()

    try:
        server_thread_tcp.start()
        #server_thread_udp.start()

    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
