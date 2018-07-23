"""
Packet sniffer in python using the pcapy python library
 
Project website
http://oss.coresecurity.com/projects/pcapy.html

Adaptado por: Amilton F. C. Junior e Dafny Garcia
"""
 
import socket
from struct import *
import datetime
import pcapy  # requires pcapy library
import sys

# global counter variable
counter = 0
# whether to show or not the packet data
showData = False


def main(argv):
    # list all devices
    devices = pcapy.findalldevs()
    # print devices

    print '-- Sniffer v1.0 - Por Amilton e Dafny - 2016 --'
    print

    # ask user to enter device name to sniff
    print "Interfaces disponiveis sao:"
    print devices
    # for d in devices:
    #    print d
     
    # dev = raw_input("Enter device name to sniff: ")
    dev = "any"
     
    print "\nCapturando em todas as interfaces..."

    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    max_bytes = 1024
    promiscuous = False
    read_timeout = 100  # in milliseconds
    cap = pcapy.open_live(dev, max_bytes, promiscuous, read_timeout)
 
    '''
    # start sniffing packets
    while(1):
        (header, packet) = cap.next()
        time_cap = datetime.datetime.now()
        bytes_cap = header.getlen()
        bytes_trunc = header.getcaplen()
        parse_packet(packet, time_cap, bytes_cap, bytes_trunc)
        # time.sleep(0.05)
    '''

    packet_limit = -1  # infinite
    cap.loop(packet_limit, parse_packet)  # capture packets


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


# function to parse a packet
def parse_packet(header, packet):
    # global variables
    global counter
    global showData

    counter += 1
    print "\n[Capturado pacote #%d] - (Pressione CTRL + C e aguarde para encerrar o programa)" % counter

    time_cap = datetime.datetime.now()
    bytes_cap = header.getlen()
    bytes_trunc = header.getcaplen()

    # parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
 
    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 or True:
        print ("%s: capturados %d bytes, truncado para %d bytes" % (
            time_cap, bytes_cap, bytes_trunc))

        print 'MAC de destino: ' + eth_addr(packet[0:6]) + ' MAC de origem: ' + eth_addr(
            packet[6:12]) + ' Protocolo: ' + str(eth_protocol)

        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]
         
        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)
 
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
 
        print 'Versao: ' + str(version) + ' Comprimento do cabecalho IP: ' + str(ihl) + ' TTL: ' + str(ttl) +\
              ' Protocolo: ' + str(protocol) + ' Endereco de origem: ' + str(s_addr) +\
              "\nEndereco de destino: " + str(d_addr)
 
        # TCP protocol
        if protocol == 6:
            print 'MAC de destino: ' + eth_addr(packet[0:6]) + ' MAC de origem: ' + eth_addr(
                packet[6:12]) + ' Protocolo: TCP'

            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
 
            # now unpack them :)
            tcph = unpack('!HHLLBBHHH', tcp_header)
             
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
             
            print 'Porta de origem: ' + str(source_port) + ' Porta de destino: ' + str(dest_port) + ' Sequencia: ' +\
                  str(sequence) + ' Acknowledgement: ' + str(acknowledgement) +\
                  ' Comprimento do cabecalho TCP: ' + str(tcph_length)
             
            h_size = eth_length + iph_length + tcph_length * 4
            # data_size = len(packet) - h_size
             
            # get data from the packet
            data = packet[h_size:]

            if showData:
                print 'Dados: <<' + data.rstrip('\n\t') + '>>'
 
        # ICMP Packets
        elif protocol == 1:
            print 'MAC de destino: ' + eth_addr(packet[0:6]) + ' MAC de origem: ' + eth_addr(
                packet[6:12]) + ' Protocolo: ICMP'

            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]
 
            # now unpack them :)
            icmph = unpack('!BBH', icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            print 'Tipo: ' + str(icmp_type) + ' Codigo: ' + str(code) + ' Checksum: ' + str(checksum)
             
            h_size = eth_length + iph_length + icmph_length
            # data_size = len(packet) - h_size
             
            # get data from the packet
            data = packet[h_size:]

            if showData:
                print 'Dados: <<' + data.rstrip('\n\t') + '>>'
 
        # UDP packets
        elif protocol == 17:
            print 'MAC de destino: ' + eth_addr(packet[0:6]) + ' MAC de origem: ' + eth_addr(
                packet[6:12]) + ' Protocolo: UDP'

            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            # now unpack them :)
            udph = unpack('!HHHH', udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            print 'Porta de origem: ' + str(source_port) + ' Porta de destino: ' + str(dest_port) +\
                  ' Comprimento: ' + str(length) + ' Checksum: ' + str(checksum)
             
            h_size = eth_length + iph_length + udph_length
            # data_size = len(packet) - h_size
             
            # get data from the packet
            data = packet[h_size:]

            if showData:
                print 'Dados: <<' + data.rstrip('\n\t') + '>>'
 
        # some other IP packet like IGMP
        else:
            h_size = eth_length + iph_length + 1
            # data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]

            if showData:
                print 'Dados: <<' + data.rstrip('\n\t') + '>>'

            print 'Obs.: Protocolo nao eh TCP/UDP/ICMP'
 
if __name__ == "__main__":
    main(sys.argv)
