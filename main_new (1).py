hiddenSSIDs = dict()
# initialize the networks dataframe that will contain all access points nearby
import pandas
from scapy.all import *
# initialize the networks dataframe that will contain all access points nearby
from scapy.layers.dot11 import Dot11Beacon

myBeacon = {}
myWlanNames = {}
list_users = []
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
wlan_name = ""


# set the index BSSID (MAC address of the AP)
# networks.set_index("BSSID", inplace=True)


def PacketHandler(packet):
    if packet.haslayer(Dot11Beacon):
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2 in myBeacon:
                myBeacon[packet.addr2] = myBeacon[packet.addr2] + 1
            elif len(packet.info) > 0:
                myBeacon[packet.addr2] = 1
                myWlanNames[packet.info.decode('UTF-8')] = packet.addr2
                
 
def searchUsers(packet):
    # if packet.haslayer(Dot11Beacon):
        if packet.addr1  == myWlanNames[wlan_name]:
           if packet.FCfield:
              DS = packet.FCfield & 0x3
              to_ds = DS & 0x1 != 0
              from_ds = DS & 0x2 != 0
              print(f'to_ds={ to_ds},from_ds={from_ds}')
              if to_ds and not from_ds and  packet.addr2 not in list_users:
                 list_users.append(packet.addr2)






if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlp0s20f3"
    # start sniffing
    # os.system(f"iwconfig {interface} channel ")
    sniff(prn=PacketHandler, iface=interface, timeout=15)
    print(myBeacon)
    print(myWlanNames)
    wlan_name = input("Choose wlan to attack")
    print(f'start search users from {wlan_name}')
    sniff(prn=searchUsers, iface=interface, timeout=60)
    print(f'list of isers in {wlan_name}\n{list_users}\n choose your victim')
    victem = input("Choose user to attack")
    print(list_users)