#!/usr/bin/env python
# coding: utf-8

# In[1]:


#Python modules required to be imported 
import dpkt
import struct
import os
import collections
import math


# In[2]:


class Packet:
    """
    Packet class will be used to parse packet bytes
    """
    valid_packet = True

    def __init__(self, timestamp, byte_info):
        self.time_stamp = timestamp
        self.byte_info  = byte_info
        self.packet_size = len(byte_info)
    
    def parse_packet_info(self):
        """
        Here, we analyze and fetch different fields in TCP header from byte info
        """
        try:
            self.src_ip1    = int.from_bytes(self.byte_info[26:27], byteorder='big')
            self.src_ip2    = int.from_bytes(self.byte_info[27:28], byteorder='big')
            self.src_ip3    = int.from_bytes(self.byte_info[28:29], byteorder='big')
            self.src_ip4    = int.from_bytes(self.byte_info[29:30], byteorder='big')
            self.src_ip     = str(self.src_ip1) + '.' + str(self.src_ip2) + '.' + str(self.src_ip3) + '.' + str(self.src_ip4)
            self.dest_ip1   = int.from_bytes(self.byte_info[30:31], byteorder='big')
            self.dest_ip2   = int.from_bytes(self.byte_info[31:32], byteorder='big')
            self.dest_ip3   = int.from_bytes(self.byte_info[32:33], byteorder='big')
            self.dest_ip4   = int.from_bytes(self.byte_info[33:34], byteorder='big')
            self.dest_ip    = str(self.dest_ip1) + '.' + str(self.dest_ip2) + '.' + str(self.dest_ip3) + '.' + str(self.dest_ip4)
            self.src_port   = str(int.from_bytes(self.byte_info[34:36], byteorder='big'))
            self.dest_port  = str(int.from_bytes(self.byte_info[36:38], byteorder='big'))
            self.seq_num    = str(int.from_bytes(self.byte_info[38:42], byteorder='big'))
            self.ack_num    = str(int.from_bytes(self.byte_info[42:46], byteorder='big'))
            option          = int.from_bytes(self.byte_info[46:47], byteorder='big')
            self.header_len = 4*(option>>4)
            flags           = int.from_bytes(self.byte_info[47:48], byteorder='big')
            self.wndsize    = str(int.from_bytes(self.byte_info[48:50], byteorder='big'))
            self.check_sum  = str(int.from_bytes(self.byte_info[50:52], byteorder='big'))
            self.urgent_ptr = str(int.from_bytes(self.byte_info[52:54], byteorder='big'))
            self.mss        = int.from_bytes(self.byte_info[56:58], byteorder='big')
            self.payload    = self.byte_info[34+self.header_len:]
            self.payload_len= len(self.payload)
            #print(self.payload_len)
            
            self.fin = flags&1
            flags    = flags>>1
            self.syn = str(flags&1)
            flags    = flags>>1
            self.rst = flags&1
            flags    = flags>>1
            self.psh = flags&1
            flags    = flags>>1
            self.ack = str(flags&1)
            flags    = flags>>1
            self.urg = flags&1
            
            
        except:
            #if exception occurs that means it is not  a valid packet.
            self.valid_packet = False           


# In[3]:


class conn_description:
    """
    Description of a connection through source and destination port
    """
    packets = []
    def __init__(self, src_port, dest_port):
        self.src_port = src_port
        self.dest_port = dest_port


# In[4]:


def fetch_packet_list(packets):
    """
    Function to parse the packets and print out information about each packet in a pcap file.
    """
    packet_list  = []
    #print("Enter into packet parser")
    for ts, byte_info in packets:
        packet = Packet(ts, byte_info)
        packet.parse_packet_info()
        #packet.parse_packet_http()
        if packet.valid_packet:
            packet_list.append(packet)
        else:
            print("Discard the packet")
    #print("Successfully parsed the pcap file, now returning the packet_list")
    return packet_list


# In[5]:


def packet_segregation(packet_list, conn_list, conn_packet_dict):
    
    for pkt in packet_list:
        for conn_key in conn_list:
            #segregate packets based on src port and dest port
            if (((pkt.src_port == conn_key.dest_port) and (pkt.dest_port == conn_key.src_port)) or ((pkt.src_port == conn_key.src_port) and (pkt.dest_port == conn_key.dest_port))):
                #print(conn_key)
                conn_packet_dict[conn_key].append(pkt)

    return conn_packet_dict


# In[6]:


def connection_segregation(packet_list):
    conn_packet_dict = collections.defaultdict(list)
    conn_list = []
    count = 0
    for pkt in packet_list:
        count += 1
        
        if pkt.syn == "1" and pkt.ack == "1":
            conn = conn_description(pkt.src_port, pkt.dest_port)
            conn_list.append(conn)
     
    return packet_segregation(packet_list, conn_list, conn_packet_dict)
    


# In[7]:


def http_get_response(packet_list):
    pkt_dict = {}
    list_of_gets = []
    for pkt in packet_list:
        pkt_dict[pkt.seq_num] = pkt
        if str(pkt.payload).find('GET') == -1:
            continue
        else:
            list_of_gets.append(pkt)

    assembled = []
    tcp_seg = []
    pkt_type = []
    
    for g in list_of_gets:
        if str(g.payload).find('HTTP') < str(g.payload).find('Connection'):
            end = str(g.payload).find('Connection')
        else:
            end = str(g.payload).find('HTTP')
        pkt_type.append(str(g.payload)[str(g.payload).find('GET'):end])
        g_ack_no = g.ack_num
        next_pkt = pkt_dict.get(g_ack_no)        
        while next_pkt:
            tcp_seg.append((next_pkt.src_port, next_pkt.dest_port, next_pkt.seq_num, next_pkt.ack_num))
            payload_len = next_pkt.payload_len
            g_ack_no = int(g_ack_no) + payload_len
            next_pkt = pkt_dict.get(str(g_ack_no))
            if next_pkt.fin == 1:
                break
        assembled.append(tcp_seg)
        
    for i in range(0,len(assembled)):
        print(pkt_type[i])
        for j in assembled[i]:
            print(j)
    return assembled


# In[8]:


def fetch_http_tcp_connections(packet_list):
    conn_tcp, pkt_cnt, payload = 0 , 0 , 0
    
    for pkt in packet_list:
        pkt_cnt += 1
        payload += pkt.packet_size
        if pkt.syn == "1" and pkt.ack == "1":
            conn_tcp += 1
    return str(conn_tcp),str(pkt_cnt),str(payload)


# In[9]:


def print_http_tcp_connections(packet_list, conn_tcp, pkt_cnt, payload):
    #Print function for HTTP TCP connections
    time_taken = str(packet_list[-1].time_stamp - packet_list[0].time_stamp)
    print("\nNo of tcp connections:{0}".format(conn_tcp))
    print("Time Taken to fetch response: {0}".format(time_taken))
    print("Total number of packets: {0}".format(pkt_cnt))
    print("Raw bytes: {0}".format(payload))


# In[10]:


if __name__ == '__main__':
    #Read packet capture(pcap) file using dpkt module.
    
    #PART C.1
    print("Running code for http_1080.pcap")
    pcap_file_path = os.path.abspath("http_1080.pcap")
    packets = dpkt.pcap.Reader(open(pcap_file_path, 'rb'))    
    packet_list = fetch_packet_list(packets)
    conn_packet_dict = connection_segregation(packet_list)
    
    for conn in conn_packet_dict:
        assembled = http_get_response(conn_packet_dict[conn])
        
    #PART C.2 and C.3
    conn_tcp, pkt_cnt, payload = fetch_http_tcp_connections(packet_list)        
    print_http_tcp_connections(packet_list, conn_tcp, pkt_cnt, payload)
    
    #Calling for file second
    print("\nRunning code for tcp_1081.pcap")
    pcap_file_path = os.path.abspath("tcp_1081.pcap")
    packets = dpkt.pcap.Reader(open(pcap_file_path, 'rb'))    
    packet_list = fetch_packet_list(packets) 
    conn_tcp, pkt_cnt, payload = fetch_http_tcp_connections(packet_list)        
    print_http_tcp_connections(packet_list, conn_tcp, pkt_cnt, payload)
    
    #Calling for file third
    print("\nRunning code for tcp_1082.pcap")
    pcap_file_path = os.path.abspath("tcp_1082.pcap")
    packets = dpkt.pcap.Reader(open(pcap_file_path, 'rb'))    
    packet_list = fetch_packet_list(packets) 
    conn_tcp, pkt_cnt, payload = fetch_http_tcp_connections(packet_list)        
    print_http_tcp_connections(packet_list, conn_tcp, pkt_cnt, payload) 


# In[ ]:




