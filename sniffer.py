import socket
import struct
import textwrap
import time
import csv
import sys
import select
import time
inputSrc = [sys.stdin]

with open('csvfile.csv', 'w') as out:
	writer=csv.writer(out)
	writer.writerow(['Source MAC','Destination MAC','Protocol','Service','Source Address','Destination Address','Sequence Number','Acknowledgement Number','SYN Bit','ACK Bit','FIN Bit','Src Bytes','Time Stamp'])

class Pcap():
    def __init__(self, filename, link_type=1):
        self.pcap = open(filename, 'wb')
        self.pcap.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0,
                                    65535, link_type))
    
    def write(self, packet):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(packet)
        self.pcap.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap.write(packet)
    
    def close(self):
        self.pcap.close()

def format_multiline(prefix, string, length=80):
    length = length - len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if length % 2: length -= 1
    return '\n'.join([prefix + line
                      for line in textwrap.wrap(string, length)])

def mac(address):
    return (':'.join(map('{:02x}'.format, address))).upper()

def ethernet_frame(data):
    destination, sourcem, protocol = struct.unpack('! 6s 6s H', data[:14])
    return mac(destination), mac(sourcem), socket.htons(protocol), data[14:]

def ipv4(address):
    return '.'.join(map(str, address))

def ipv4_packet(data):
    version_header_length = data[0]
            
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    return (version, header_length, ttl, protocol, ipv4(source), ipv4(target),
            data[header_length:])

def icmp_packet(data):
    type, code, checksum = struct.unpack('! B B H', data[:4])
    return type, code, checksum, data[4:]  

def tcp_segment(data):
    (source_port, destination_port, sequence, acknowledgment,
     offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    
    return (source_port, destination_port, sequence, acknowledgment, flag_urg,
            flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:])

def udp_segment(data):
    source_port, destination_port, length = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, length, data[8:]

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) == 2:
        pcap = Pcap(sys.argv[1])
    else:
        pcap = None
    
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    connection.bind(("ens33",0))
    timeout=time.time()+10
    while time.time()<timeout:
        data, address = connection.recvfrom(65535)
        
        if pcap is not None: pcap.write(data)
        
        destination, sourcem, protocol, data = ethernet_frame(data)
        
        print('Ethernet Frame:')
        print(('| - Destination: {}, Source: {}, Protocol: {}')
              .format(destination, sourcem, protocol))
        
        if protocol == 8:
            (version, header_length, ttl, protocol, source, target,
             data) = ipv4_packet(data)
            
            print('| - IPv4 Packet:')
            print(('    | - Version: {}, Header Length: {}, TTL: {},'
                   ).format(version, header_length, ttl))
            print(('    | - Protocol: {}, Source: {}, Target: {}'
                   ).format(protocol, source, target))
            
            if protocol == 1:
                type, code, checksum, data = icmp_packet(data)
                print('    | - ICMP Packet:')
                print(('        | - Type: {}, Code: {}, Checksum: {},'
                       ).format(type, code, checksum))
                datalength=0
                timest=time.time()
                with open('csvfile.csv', 'a') as out:
                        writer=csv.writer(out)
                        writer.writerow([sourcem, destination, protocol, 66, source, target, "n", "n", "n", "n", "n", datalength, timest])
                
            elif protocol == 6:
                (source_port, destination_port, sequence, acknowledgment,
                 flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,
                 data) = tcp_segment(data)
                print('    | - TCP Segment:')
                print(('        | - Source Port: {}, Destination Port: {}'
                       ).format(source_port, destination_port))
                print(('        | - Sequence: {}, Acknowledgment: {}'
                       ).format(sequence, acknowledgment))
                print('        | - Flags:')
                print(('             | - URG: {}, ACK: {}, PSH: {}, RST: {}, '
                       'SYN: {}, FIN:{}').format(flag_urg, flag_ack, flag_psh,
                                                 flag_rst, flag_syn, flag_fin))
                datalength=0
                timest=time.time()
                datalength=len(data)+header_length
                if (source_port==80 or source_port==443 or destination_port==80 or destination_port==443):
                        service=33
                with open('csvfile.csv', 'a') as out:
                        writer=csv.writer(out)
                        writer.writerow([sourcem, destination, protocol, 33, source, target, sequence, acknowledgment, flag_syn, flag_ack, flag_fin, datalength, timest])            
            elif protocol == 17:
                source_port, destination_port, length, data = udp_segment(data)
                print('    | - UDP Segment:')
                print(('        | - Source Port: {}, Destination Port: {}, '
                       'Length: {}').format(source_port, destination_port, length))
                      
            else:
                print('    | - Data:')
                print(format_multiline('        | - ', data))
                                  
        else:
            print('| - Data:')
            print(format_multiline('    | - ', data))

        keypress = select.select(inputSrc, [], [], 0)[0]
        while keypress:
        
         for src in keypress:
            line = src.readline()
            if not line:
                inputSrc.remove(src)
            else:
                # The "enter" key prints out a menu
                if line == "\n":
                    print("Sniffing Paused\nOptions: [0]: Quit  [any other key]: Resume")
                elif line.rstrip() == "0":
                    exit(0)
                elif len(line) >= 1: #any other key
                    print("Resuming...")
                    keypress = None
        
print()
