import socket
import struct
import time
import argparse
import sys
import dns.resolver
import re


def is_valid_ip(ip):
    con = True
    bytes = ip.split('.')
    if len(bytes) != 4:
        con = False  
    for i in range(len(bytes)):
        if re.search("[0-9]+",bytes[i]) is None:
            con = False
        if int(bytes[i]) > 255 or int(bytes[i]) < 0:
            con = False
    return con


def create_socket():
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error as e:
        errno, msg = e.args
        if errno == 1:
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise
    return my_socket


def resolve_destination(destination):
    try:
        answers = dns.resolver.resolve(destination, 'A')
        destination_ip = answers[0].address
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print('Invalid hostname or IP address.')
        sys.exit(1)
    except (dns.resolver.LifetimeTimeout):
        print("DNS resolution timeout")
        sys.exit(1)

    return destination_ip


def calculate_checksum(data):
    checksum = 0
    count_to = (len(data) // 2) * 2
    for count in range(0, count_to, 2):
        checksum += (data[count + 1] << 8) + data[count]
    if count_to < len(data):
        checksum += data[len(data) - 1]
    checksum &= 0xFFFFFFFF
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += (checksum >> 16)
    return ~checksum & 0xFFFF


def send_ping_request(destination_ip, my_socket):
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_identifier = 12345
    icmp_sequence = 1
    icmp_payload = b'0'
    timeout = 3

    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)
    icmp_checksum = socket.htons(calculate_checksum(icmp_header + icmp_payload))
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)

    t = time.time()
    my_socket.sendto(icmp_header + icmp_payload, (destination_ip, 0))
    my_socket.settimeout(timeout)
    return t


def receive_ping_reply(my_socket, start_time):
    try:
        while True:
            received_packet, _ = my_socket.recvfrom(1024)
            receive_time = time.time()
            icmp_header = struct.unpack('!BBHHH', received_packet[20:28])
            if icmp_header[0] == 0 and icmp_header[1] == 0:
                t = f'{int((receive_time - start_time) * 1000)}ms'
                print(f'Ping successful: time={t}')
                return t
    except socket.timeout:
        print('Request Timed out.')


def ping(destination):
    if is_valid_ip(destination):
        destination_ip = destination
    else: 
        destination_ip = resolve_destination(destination)
    icmp_socket = create_socket()
    start_time = send_ping_request(destination_ip, icmp_socket)
    return receive_ping_reply(icmp_socket, start_time)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Ping tool in the terminal.')
    parser.add_argument('destination', help='IP address or domain to ping')
    parser.add_argument('packet_count', help='Number of packets to ping')
    destination , packet_count = parser.parse_args().destination , int(parser.parse_args().packet_count)
    print(f"Pinging {destination} with {packet_count*8} bytes of data:")
    lost = 0
    sumation = 0
    for i in range(packet_count):
        temp = ping(destination)
        if temp == None :
            lost += 1
        else:
            sumation += int(temp[:-2])

    print("PACKETS** sent:",packet_count,"received:",packet_count-lost,"lost:", lost,f"({lost/packet_count*100}%)loss")
    if packet_count!=lost:
        print("Approximate round trip times in milli-seconds:\n\tAverage = ",sumation/(packet_count-lost),"ms")