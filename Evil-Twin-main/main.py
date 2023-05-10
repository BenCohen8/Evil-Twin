import os


def install(wlan):
    os.system("apt install net tools")
    os.system("apt-get install hostapd dnsmasq apache2")


def hostapd(ssid, bssid):
    text = f'interface=wlan1\n' \
           f'driver=nl80211\n' \
           f'ssid={ssid}\n' \
           f'hw_mode=g\n' \
           f'channel=11\n' \
           f'macaddr_acl=0\n' \
           f'ignore_broadcast_ssid=0\n'
    # f'bssid={bssid}\n' \

    with open("hostapd.conf", "w") as f:
        f.write(text)
    f.close()


def DNSmask():
    text = "interface=wlan1\n" \
           "dhcp-range=192.168.0.2, 192.168.0.30, 255.255.255.0, 12h\n " \
           "dhcp-option=3 ,192.168.0.1\n" \
           "dhcp-option=6 ,192.168.0.1\n" \
           "server=8.8.8.8\n" \
           "log-queries\n" \
           "log-dhcp\n" \
           "listen-address=127.0.0.1"
    with open('dnsmasq.conf', 'w') as f:
        f.write(text)
    f.close()


if __name__ == '__main__':
    os.system("iwconfig")
    interface = input("choose interface")
    # change interface name to wlan1
    os.system("  rfkill unblock wifi; rfkill unblock all")
    os.system(f' ip link set {interface} down')
    os.system(f' ip link set {interface} name wlan1')
    os.system(" ip link set wlan1 up")
    os.system(" ip link set wlan1 down")
    os.system(" ifconfig wlan1 up 192.168.0.1 netmask 255.255.255.0")
    os.system(" route add -net 192.168.0.0 netmask 255.255.255.0 gw 192.168.0.1")
    os.system(" ip link set wlan1 up")

    os.system("systemctl stop systemd-resolved")
    os.system("iptables --table nat --append POSTROUTING --out-interface wlp2s0 -j MASQUERADE")
    os.system("iptables --append FORWARD --in-interface wlan1 -j ACCEPT")
    DNSmask()
    hostapd("ben", "12:34:56:78:90:12")
    os.system("sysctl net.ipv4.ip_forward=1")
    os.system("systemctl stop systemd-resolved")

    #os.system("sudo hostapd hostapd.conf ")
    #os.system("dnsmasq -C dnsmasq.conf -d")
