import argparse
import time
import socket
import sys
from struct import pack



def create_ip_header(source_ip, dest_ip):

    #source_ip = '192.168.1.101'
    #dest_ip = '192.168.1.1'	# or socket.gethostbyname('www.google.com')

    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0	# kernel will fill the correct total length
    ip_id = 54321	#Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0	# kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )	# Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    # https://docs.python.org/3/library/struct.html
    ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    return ip_header

def create_tcp_header(source_ip, dest_ip, source_port, dest_port, user_data):
    # tcp header fields
    #tcp_source = 1234	# source port
    #tcp_dest = 80	# destination port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons (5840)	#	maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    pseudo_header = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length)
    pseudo_header = pseudo_header + tcp_header + user_data.encode()

    tcp_check = checksum(pseudo_header)
    #print tcp_checksum

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH' , source_port, dest_port, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)

    return tcp_header

# checksum functions needed for calculation checksum
def checksum(msg):
    print(msg)
    s = 0

	# loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s


def main():

    #parser = argparse.ArgumentParser()
    #https://docs.python.org/3/howto/argparse.html
    #parser.parse_args()




    # socket: https://www.binarytides.com/raw-socket-programming-in-python-linux/

    #create a raw socket
    try:
    	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as error_msg:
    	print('Socket could not be created. Error Message : ', error_msg)
    	sys.exit()

    # tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # now start constructing the packet
    packet = ''

    ### TODO: GET IP ADDRESS AND PORTS FROM ARGPARSE
    source_ip = '1.2.3.4'
    dest_ip = '10.10.2.0'
    source_port = 1234
    dest_port = 22

    user_data = 'Hello, how are you'

    ip_header = create_ip_header(source_ip, dest_ip)

    tcp_header = create_tcp_header(source_ip, dest_ip, source_port, dest_port, user_data)

    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header + user_data.encode()

    # increase count to send more packets
    count = 3

    for i in range(count):
        print('sending packet...')
        # Send the packet finally - the port specified has no effect
        s.sendto(packet, (dest_ip , 0 ))	# put this in a loop if you want to flood the target
        print('send')
        time.sleep(1)

    print('all packets send')


if __name__ == '__main__':
    main()
