import scapy.all as scapy
import subprocess

def scan(iface):
    ap_list = []
    print("[+] Scanning for Access Points ...")
    scapy.sniff(iface=iface, store=False, prn=ap_detect)
    print("[+] Scanning Complete")
    return ap_list

def ap_detect(pkt):
    if pkt.haslayer(scapy.Dot11Beacon):
        if pkt.info not in ap_list:
            ap_list.append(pkt.info)
            print("[+] Detected Access Point: " + pkt.info)

def check_if_fake_ap(iface):
    real_ap = []
    fake_ap = []
    ap_list = scan(iface)
    for ap in ap_list:
        cmd = "sudo iwlist " + iface + " scanning | grep " + ap
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        if "Authentication Suites" in str(out):
            real_ap.append(ap)
            print("[+] Real Access Point Detected: " + ap)
        else:
            fake_ap.append(ap)
            print("[+] Fake Access Point Detected: " + ap)

    return real_ap, fake_ap

def disconnect_from_fake_ap(iface, fake_ap):
    for ap in fake_ap:
        cmd = "sudo iwconfig " + iface + " essid off"
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        print("[+] Disconnected from Fake Access Point: " + ap)

def connect_to_real_ap(iface, real_ap):
    for ap in real_ap:
        cmd = "sudo iwconfig " + iface + " essid " + ap
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        print("[+] Connected to Real Access Point: " + ap)

def defence():
    iface = "wlan0"
    real_ap, fake_ap = check_if_fake_ap(iface)
    disconnect_from_fake_ap(iface, fake_ap)
    connect_to_real_ap(iface, real_ap)