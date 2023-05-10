import signal
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, RadioTap
ap_list = []
ssid_list = []
interface = ""
ssid = ""
real_ap_mac = ""
client_mac=""
attacker_mac =""
evil = ""
attacked = False
count = 0
first = True

def change_to_monitor_mode(interface):
    """
    In this function we change the network card mode to Monitor Mode
    by writing some commands to the OS system
    """
    os.system('sudo airmon-ng check kill >/dev/null 2>&1')
    os.system('sudo ifconfig ' + str(interface) + ' down')
    os.system('sudo iwconfig ' + str(interface) + ' mode monitor')
    os.system('sudo ifconfig ' + str(interface) + ' up')


def network_scanning():
    """
    This function checks if there are two different MAC addresses with the same SSID
    """
    sniff(iface=interface, stop_filter=packet_handler, timeout=60)


def packet_handler(packet):
    global ap_list, ssid_list, evil, real_ap_mac, attacker_mac

    dot11 = packet.getlayer(Dot11)
    if dot11 is not None and dot11.type == 0 and dot11.subtype == 8:
        if dot11.addr2 is not None:
            ssid = dot11.info.decode("utf-8")
            if ssid not in ssid_list:
                ap_list.append(dot11.addr2)
                ssid_list.append(ssid)
            else:
                i = ssid_list.index(ssid)
                real_ap_mac = ap_list[i]
                if real_ap_mac != dot11.addr2:
                    print("\nExist Twin AP, might be under attack !! ")
                    evil = ssid
                    attacker_mac = dot11.addr2
                    time.sleep(1)
                    return True
        return False
def deauth(interface):
    timeout = time.time() + 60  
    while time.time() < timeout and not attacked:
        sniff(iface=interface, prn=deauth_handler, timeout=30)

def deauth_handler(packet):
    global attacked, count, first, real_ap_mac, client_mac
  
    if packet.haslayer(Dot11Deauth):
        
        if packet.addr3 == real_ap_mac:
            count += 1
         
            if count > 40 and first:
                attacked = True
                first = False
                print("\nYou are under attack!")
                time.sleep(1)
                client_mac = str(packet.addr1)
                return True
    return False

def attack_attacker(interface, attacker_mac, attacked_mac):
    setChannel()
    print("\nStart sending Deauthentication packets.")
    dot11 = Dot11(type=0, subtype=12, addr1=attacked_mac, addr2=attacker_mac, addr3=attacker_mac)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)  # create attack frame
    sendp(packet, inter=0.1, count=100, iface=interface, verbose=0)
    dot11 = Dot11(type=0, subtype=12, addr1=attacker_mac, addr2=attacked_mac, addr3=attacked_mac)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)  # create attack frame
    sendp(packet, inter=0.1, count=100, iface=interface, verbose=0)





def reset():
    global evil, attacked, attacked_mac, ap_mac, count, first, ssid_list, ap_list
    count = 0
    first = True
    attacked = False
    attacked_mac = []
    attacked = ''
    evil = ''
    ap_mac = ''
    ap_list = []
    ssid_list = []


def defence_main(interface):
    global evil, attacked, attacked_mac, ap_mac

    while True:
        print("\nstarting scan if you want to stop press ctrl+c")
        time.sleep(1)

        print("\ncheck if exist evil twin in the network .. it will take minutes")
        time.sleep(1)
        network_scanning()

        if evil:  
            print("\nStart scanning for deauth attack .. it will take a minute")
            time.sleep(1)
            attacked_mac = check_for_deauth(interface)

            if attacked_mac:
                print("\nAn attacker has been detected, starting counter-attack...")
                time.sleep(1)
                attack_attacker(interface, attacker_mac, attacked_mac)
                print("\nThe attacker has been attacked, you are safe")
                time.sleep(1)
                
            else:
                print("\nNo deauth attack detected.")
                time.sleep(1)
        else:
            print("\nNo attack detected, you are safe")
            time.sleep(1)
        reset()    


def check_for_deauth(interface):
    """
    Check if there are any deauth packets targeting the real AP MAC address.
    Returns the MAC address of the client being attacked, if any.
    """
    print("Checking for deauth packets...")
    global attacked, first, real_ap_mac, client_mac
    attacked = False
    first = True
    count = 0
    client_mac = None

def network_scanning():
    """
    This function checks if there are two different MAC addresses with the same SSID
    """
    global ap_list, ssid_list, evil, real_ap_mac, client_mac, attacker_mac, attacked
    sniff(iface=interface, stop_filter=packet_handler, timeout=60)

def setChannel(channel):
    os.system('iwconfig %s channel %d' % (interface, channel))


def exit_handler(signum, frame):
    print("\nGoodye !! ")
    sys.exit()


def defence():
    interface = input("enter the name of the interface you want to work with: ")
    change_to_monitor_mode(interface)
    time.sleep(2)

    while True:
        signal.signal(signal.SIGINT, exit_handler)
        defence_main(interface)
        time.sleep(5)
