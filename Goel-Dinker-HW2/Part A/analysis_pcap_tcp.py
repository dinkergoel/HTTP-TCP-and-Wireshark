#!/usr/bin/env python
# coding: utf-8

# **PART A**

# In[2]:


#Python modules required to be imported 
import dpkt
import struct
import os
import collections
import math


# In[3]:


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


# In[4]:


class conn_description:
    """
    Description of a connection through source and destination port
    """
    packets = []
    def __init__(self, src_port, dest_port):
        self.src_port = src_port
        self.dest_port = dest_port


# In[5]:


def fetch_packet_list(packets):
    """
    Function to parse the packets and print out information about each packet in a pcap file.
    """
    packet_list  = []
    #print("Enter into packet parser")
    for ts, byte_info in packets:
        packet = Packet(ts, byte_info)
        packet.parse_packet_info()
        if packet.valid_packet:
            packet_list.append(packet)
        else:
            print("Discard the packet")
    print("Successfully parsed the pcap file, now returning the packet_list")
    return packet_list


# In[6]:


def packet_segregation(packet_list, conn_list, conn_packet_dict):
    
    for pkt in packet_list:
        for conn_key in conn_list:
            #segregate packets based on src port and dest port
            if (((pkt.src_port == conn_key.dest_port) and (pkt.dest_port == conn_key.src_port)) or ((pkt.src_port == conn_key.src_port) and (pkt.dest_port == conn_key.dest_port))):
                #print(conn_key)
                conn_packet_dict[conn_key].append(pkt)

    return conn_packet_dict


# In[7]:


def connection_segregation(packet_list):
    conn_packet_dict = collections.defaultdict(list)
    conn_list = []
    count = 0
    for pkt in packet_list:
        count += 1
        
        if pkt.syn == "1" and pkt.ack == "1":
            # print str(packet.srcPort) + ":" + str(packet.destPort) 
            conn = conn_description(pkt.src_port, pkt.dest_port)
            #conn.packets = []
            conn_list.append(conn)
     
    return packet_segregation(packet_list, conn_list, conn_packet_dict)
    


# In[8]:


def fetch_two_transactions(conn_packet_dict):
    pkt_sender = conn_packet_dict[conn][2]
    for pkt in conn_packet_dict[conn][3:]:
        if pkt.seq_num == pkt_sender.ack_num:
            pkt_receiver = pkt
            break
            
    count = 0
    for pkt in conn_packet_dict[conn][3:]:
        if pkt.seq_num == pkt_receiver.ack_num:
            pkt_sender_1 = pkt
            break
    for pkt in conn_packet_dict[conn][3:]:
        if pkt.seq_num == pkt_sender_1.ack_num:
            count+=1
            if count > 1:
                pkt_receiver_1 = pkt
                break
                
    return pkt_sender, pkt_receiver, pkt_sender_1, pkt_receiver_1    


# In[9]:


def print_transactions(pkt_sender, pkt_receiver,pkt_sender_1, pkt_receiver_1):
    print("---------------------------------------------------")    
    print("\nFIRST TRANSACTION:")
    print("\nAt sender:",)
    print("\n seq_no:{0}, ack_no:{1}, window_size:{2}".format(pkt_sender.seq_num, pkt_sender.ack_num, pkt_sender.wndsize))
    print("\nAt receiver:")
    print("\n seq_no:{0}, ack_no:{1}, window_size:{2}".format(pkt_receiver.seq_num, pkt_receiver.ack_num, pkt_receiver.wndsize))
    
    print("\nSECOND TRANSACTION:")
    print("\nAt sender:",)
    print("\n seq_no:{0}, ack_no:{1}, window_size:{2}".format(pkt_sender_1.seq_num, pkt_sender_1.ack_num, pkt_sender_1.wndsize))
    print("\nAt receiver:")
    print("\n seq_no:{0}, ack_no:{1}, window_size:{2}".format(pkt_receiver_1.seq_num, pkt_receiver_1.ack_num, pkt_receiver_1.wndsize))
    print("---------------------------------------------------")
        


# In[10]:


def calculate_throughput(packet_list):
    payload_sum, end_time , start_time ,time_taken = 0,0,0, 0
    flag = True
    
    for pkt in packet_list:
        payload_sum = payload_sum + pkt.packet_size
    
    start_time = packet_list[0].time_stamp
    end_time = packet_list[-1].time_stamp
            
    time_taken = end_time - start_time
    tp_value = (payload_sum*8.0)/(time_taken*1024*1024) 
    
    return str(tp_value)


# In[11]:


def loss_rate(packet_list):
    lost_packets = 0
    unique_from_sender = 0
    packets_with_same_seq = {}
    for pkt in packet_list:
        if pkt.src_ip == "130.245.145.12" and pkt.dest_ip == "128.208.2.198":
            packets_with_same_seq[pkt.seq_num] = packets_with_same_seq.get(pkt.seq_num,0) + 1
            unique_from_sender +=1
                      
    for key, value in packets_with_same_seq.items():
        lost_packets += value - 1 
    print("Number of lost packet:{0}".format(lost_packets))
    lr_value = lost_packets*(1.0/unique_from_sender)
    return lr_value


# In[12]:


def estimate_rtt(packet_list):
    seq_num_dict, ack_num_dict = {},{}
    count = time_taken =0
    for pkt in packet_list:
        if pkt.src_ip == "130.245.145.12" and pkt.dest_ip == "128.208.2.198":
            if pkt.seq_num in seq_num_dict:
                continue
            else:
                seq_num_dict[pkt.seq_num] = pkt.time_stamp
        elif pkt.src_ip == "128.208.2.198" and pkt.dest_ip == "130.245.145.12":
            if pkt.ack_num in ack_num_dict:
                continue
            else:
                ack_num_dict[pkt.ack_num] = pkt.time_stamp
                         
    for seq_num, ts in seq_num_dict.items():
        if seq_num in ack_num_dict:
            count += 1
            time_taken += ack_num_dict[seq_num] - ts

    rtt = time_taken/count
    
    return rtt


# In[13]:


def congestion_window(packet_list):
    window = [] #list of window sizes
    for pkt in packet_list:
        if pkt.src_ip == "130.245.145.12" and pkt.dest_ip == "128.208.2.198":
            seq_of_last_packet_from_sender = pkt.seq_num
        elif pkt.src_ip == "128.208.2.198" and pkt.dest_ip == "130.245.145.12":
            size = int(seq_of_last_packet_from_sender)-int(pkt.ack_num)
            if size == -1:
                continue
            else:
                window.append(str(size))
                if len(window) == 10:
                    break
    return window


# In[14]:


def duplicate_ack_timeout(packet_list):
    packets_with_same_seq, packets_with_same_ack = {},{}
    for pkt in packet_list:
        if pkt.src_ip == "130.245.145.12" and pkt.dest_ip == "128.208.2.198":
            packets_with_same_seq[pkt.seq_num] = packets_with_same_seq.get(pkt.seq_num,0) + 1
        elif pkt.src_ip == "128.208.2.198" and pkt.dest_ip == "130.245.145.12":
            packets_with_same_ack[pkt.ack_num] = packets_with_same_ack.get(pkt.ack_num,0) + 1
        else:
            print("Ignore the extra traffic")
            
    total_packets_lost = 0
    triple_dup_ack = 0
    
    for seq,count in packets_with_same_seq.items():
        if seq in packets_with_same_seq:
            total_packets_lost += packets_with_same_seq[seq] - 1
        if seq in packets_with_same_ack:
            if packets_with_same_ack[seq] <= 2:
                continue
            else:
                triple_dup_ack += packets_with_same_seq[seq] - 1
                
    return total_packets_lost, triple_dup_ack


# In[15]:


# MAIN PROGRAM
if __name__ == '__main__':
    #Read packet capture(pcap) file using dpkt module.
    pcap_file_path = os.path.abspath("assignment2.pcap")
    
    packets = dpkt.pcap.Reader(open(pcap_file_path, 'rb'))    
    packet_list = fetch_packet_list(packets)
    
    print("Total number of packets:" , len(packet_list))
    
    conn_count = 0 #initializing the counter
    
    #PART A.1
    for packet in packet_list:
        if packet.syn == "1" and packet.ack == "1":
            conn_count = conn_count + 1

    print("Number of TCP flows initiated from the sender:",conn_count)
    
    #PART A.2.a
    #Here, connection is segregated and packets are classified for each connection based on src and dest ports
    conn_packet_dict = connection_segregation(packet_list)
    print("First two transactions after TCP connection is set up for each TCP flow: \n")
    
    count = 0
    for conn in conn_packet_dict:
        pkt_sender, pkt_receiver, pkt_sender_1, pkt_receiver_1 = fetch_two_transactions(conn_packet_dict)
        print("Printing for Flow number: {}".format(count + 1))
        print_transactions(pkt_sender, pkt_receiver,pkt_sender_1, pkt_receiver_1)
        count+=1
    
    
    
    #PART A.2.b Throughput Calculation
    count = 1
    for conn in conn_packet_dict:
        tp = calculate_throughput(conn_packet_dict[conn])
        print("Throughput for flow {0}: {1} Mbps ".format(count, tp))
        count+=1
        
    print("---------------------------------------------------")    
    #PART A.2.c Loss rate for each flow
    count = 1
    lr = []
    for conn in conn_packet_dict:
        lr.append(loss_rate(conn_packet_dict[conn]))
        print("Loss rate for flow {0}: {1}".format(count, lr[count-1]))
        count+=1
        
    
    print("---------------------------------------------------")
    
    #PART A.2.d  Estimate the average RTT
    count = 1
    rtt = []
    for conn in conn_packet_dict:
        rtt.append(estimate_rtt(conn_packet_dict[conn]))
        print("Estimated RTT for flow {0}: {1}".format(count, rtt[count-1]))
        count+=1
        
    print("---------------------------------------------------")
    
    #PART A.2.d.2 Calculation of theoretical throughput
    mss = 1460
    for i in range(0,len(rtt)):
        tts = (math.sqrt(3/2)*mss*8)/(rtt[i] * math.sqrt(lr[i]))
        print("Theoretical throughput for flow {0}: {1} Mbps".format((i + 1), tts/(1024*1024)))
    
    print("---------------------------------------------------")
     
    #PART B.1 Congestion window 
    cw = []
    count =1
    for conn in conn_packet_dict:
        print("Calculating the first 10 congestion window sizes for Flow: {0}".format(count))
        cw = congestion_window(conn_packet_dict[conn])
        for i in cw:
            print("Congestion Window: {0}".format(i))
        count +=1

    print("----------------------------------")
    #PART B.2 Classification of retransmision between triple ack and timeouts
    cw = []
    count =1
    for conn in conn_packet_dict:
        print("Calculating the number of retransmissions due to Triple Dup Ack and Timeouts for Flow: {0}".format(count))
        total_packets_lost, triple_dup_ack = duplicate_ack_timeout(conn_packet_dict[conn])
        print("Number of retransmissions due to triple duplicate ack: {0}".format(triple_dup_ack))
        timeout = total_packets_lost - triple_dup_ack
        print("Number of retransmissions due to timeout: {0}".format(timeout))
        count += 1


# In[ ]:




