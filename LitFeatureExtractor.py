#Check if cython code has been compiled
import os
import subprocess

use_extrapolation=False #experimental correlation code
if use_extrapolation:
    print("Importing AfterImage Cython Library")
    if not os.path.isfile("AfterImage.c"): #has not yet been compiled, so try to do so...
        cmd = "python setup.py build_ext --inplace"
        subprocess.call(cmd,shell=True)
#Import dependencies
import netStat as ns
import numpy as np
print("Importing Scapy Library")
from scapy.all import *
import os.path
import subprocess


#Extracts Kitsune features from given pcap file one packet at a time using "get_next_vector()"
# If wireshark is installed (tshark) it is used to parse (it's faster), otherwise, scapy is used (much slower).
# If wireshark is used then a tsv file (parsed version of the pcap) will be made -which you can use as your input next time
class FE:
    def __init__(self,interface):
        self.curPacketIndx = 0

        ### Prep Feature extractor (AfterImage) ###
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)


    def proc_next_vector(self, packet):
        IPtype = np.nan
        timestamp = packet.frame_info.time_epoch
        framelen = packet.frame_info.len
        srcIP = ""
        dstIP = ""
        srcproto = ""
        dstproto = ""
        
        try:
            # parse network layer info from packet
            if "IP" in packet:
                if packet.ip.version == "4": 
                    IPtype = 0
                elif packet.ip.version == "6":
                    IPtype = 1
                else:
                    raise ValueError("UNKNOWN IP PROTOCOL IN USE")
                srcIP = packet.ip.src
                dstIP = packet.ip.dst

            # parse transport layer info from packet
            if "TCP" in packet:
                if packet.transport_layer == "TCP":
                    srcproto = packet.tcp.srcport
                    dstproto = packet.tcp.dstport
            elif "UDP" in packet:
                if packet.transport_layer == "UDP":
                    srcproto = packet.udp.srcport
                    dstproto = packet.udp.dstport
            else:
                srcproto = ""
                dstproto = ""

            # parse data link layer info from packet
            srcMAC = packet.eth.src
            dstMAC = packet.eth.dst

            if srcproto == "":  # L1/L2 protocol
                if "ARP" in packet: # is ARP
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = packet.arp.src_proto_ipv4  # src IP (ARP)
                    dstIP = packet.arp.dst_proto_ipv4  # dst IP (ARP)
                    IPtype = 0
                elif "ICMP" in packet:  # is ICMP
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
                    srcIP = packet.src  # src MAC
                    dstIP = packet.dst  # dst MAC
        except AttributeError as e:
            print(e)
            print("Continuing to next packet")

        # try:
        #     print(f'IPtype: {IPtype}, srcMAC: {srcMAC}, dstMAC: {dstMAC}, srcIP: {srcIP}, dstIP: {dstIP}, srcproto: {srcproto}, dstproto: {dstproto}')
        # except Exception as e:
        #     print(e)


        ### Extract Features
        try:
            return self.nstat.updateGetStats(IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto,
                                                int(framelen),
                                                float(timestamp)), srcIP
        
        except Exception as e:
            print(e)
            return []


    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())
