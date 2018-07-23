"""
Scanner de hosts ativos

Adaptado por: Amilton F. C. Junior e Dafny Garcia
"""

import socket
import struct
from ctypes import *
import os
import sys
import time
import netifaces
from netifaces import interfaces, ifaddresses, AF_INET
import threading
from netaddr import *


class Scan():
    print '-- Scanner v1.0 - Por Amilton e Dafny - 2016 --'
    print

    host = socket.gethostbyname(socket.gethostname())

    interface_list = netifaces.interfaces()
    print "Interfaces disponiveis sao:"
    print interface_list

    # define the interface
    interface = 'en0'
    print "\nUsando a interface '%s'..." % interface
    # get the addresses
    addrs = netifaces.ifaddresses(interface)
    addr = addrs[2][0]['addr'].split('.')
    netmask = addrs[2][0]['netmask'].split('.')
    # broadcast = addrs[2][0]['broadcast'].split('.')

    def get_net_size(netmask):
        binary_str = ''
        for octet in netmask:
            binary_str += bin(int(octet))[2:].zfill(8)
        return str(len(binary_str.rstrip('0')))

    # calculate network start
    net_start = [str(int(addr[x]) & int(netmask[x])) for x in range(0, 4)]

    # get CIDR notation
    subnet = '.'.join(net_start) + '/' + get_net_size(netmask)
    # print subnet

    # Mensagem para verificar a resposta
    message = "SAS2016"

    # funcao que envia um pacote UDP
    def udp_sender(subnet, message):
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for ip in IPNetwork(subnet):
            try:
                # print "Enviando pacote p/ %s" % ip
                sender.sendto(message, ("%s" % ip, 65212))
            except:
                pass


    class IP(Structure):

        _fields_ = [
            ("ihl",           c_ubyte, 4),
            ("version",       c_ubyte, 4),
            ("tos",           c_ubyte),
            ("len",           c_ushort),
            ("id",            c_ushort),
            ("offset",        c_ushort),
            ("ttl",           c_ubyte),
            ("protocol_num",  c_ubyte),
            ("sum",           c_ushort),
            ("src",           c_uint32),
            ("dst",           c_uint32)
        ]

        def __new__(self, socket_buffer=None):
            return self.from_buffer_copy(socket_buffer)

        def __init__(self, socket_buffer=None):

            self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

            self.src_address = socket.inet_ntoa(struct.pack("<I", self.src))
            self.dst_address = socket.inet_ntoa(struct.pack("<I", self.dst))

            try:
                self.protocol = self.protocol_map[self.protocol_num]
            except:
                self.protocol = str(self.protocol_num)

    class ICMP(Structure):

        _fields_ = [
            ("type",         c_ubyte),
            ("code",         c_ubyte),
            ("checksum",     c_ushort),
            ("unused",       c_ushort),
            ("next_hop_mtu", c_ushort)
        ]

        def __new__(self, socket_buffer):
            return self.from_buffer_copy(socket_buffer)

        def __init__(self, socket_buffer):
            pass

    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((host, 0))
    except socket.error, msg:
        print "Erro: %s" % msg
        # print "\nExecutar como superusuario"
        sys.exit(0)

    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print "\nBuscando hosts ativos na rede...\n"

    # Envia pacotes ICMP
    t = threading.Thread(target=udp_sender, args=(subnet, message))
    t.start()

    try:
        start = time.time()
        while (time. time() - start < 15):

            # Le a resposta
            raw_buffer = sniffer.recvfrom(65565)[0]

            # Separa o cabecalho IP
            ip_header = IP(raw_buffer[0:20])

            # Se for um pacote ICMP
            if ip_header.protocol == "ICMP":

                # Calcula o inicio do pacote ICMP
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + sizeof(ICMP)]

                # Separa cabecalho ICMP
                icmp_header = ICMP(buf)

                # Verifica se TYPE 3 e CODE 3
                if icmp_header.code == 3 and icmp_header.type == 3:
                    # Verifica se foi uma resposta
                    if IPAddress(ip_header.src_address) in IPNetwork(subnet):

                        # Verifica a mensagem magic message
                        if raw_buffer[len(raw_buffer)-len(message):] == message:
                            print "Host ativo: %s" % ip_header.src_address

    except KeyboardInterrupt:
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)