import os


def install(wlan):
    os.system("apt install net tools")
    os.system("apt-get install hostapd dnsmasq apache2")


def hostapd(ssid):
    # kill all hostapd
    os.system('service hostapd stop >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    text = f'interface=wlan1\n' \
           f'driver=nl80211\n' \
           f'ssid={ssid}\n' \
           f'hw_mode=g\n' \
           f'channel=11\n' \
           f'macaddr_acl=0\n' \
           f'ignore_broadcast_ssid=0\n'
    # f'bssid={bssid}\n' \

    with open("conf/hostapd.conf", "w") as f:
        f.write(text)
    f.close()


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
           f"addrres=/www.google.com/192.169.0.1\n" \
           f"server=8.8.8.8\n" \
           f"log-queries\n" \
           f"log-dhcp\n" \
           f"dhcp-authoritative\n" \
           f"listen-address=127.0.0.1"
    with open('conf/dnsmasq.conf', 'w') as f:
        f.write(text)
    f.close()


def conf_apache2():
    os.system('sudo chmod 777 /var/www/html')

    # update rules inside 000-default.conf of apache2
    os.system('sudo cp -f 000-default.conf /etc/apache2/sites-enabled')
    os.system('a2enmod rewrite >/dev/null 2>&1')  # enable the mod_rewrite in apache
    os.system('service apache2 restart >/dev/null 2>&1')  # reload and restart apache2


if __name__ == '__main__':
    os.system("iwconfig")
    interface = input("choose interface")

    # Clear port 53
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved>/dev/null 2>&1')

    # change interface name to wlan1
    os.system("  rfkill unblock wifi; rfkill unblock all")
    os.system(f' ip link set {interface} down')
    os.system(f' ip link set {interface} name wlan1')
    os.system(" ip link set wlan1 up")
    os.system(" ip link set wlan1 down")
    os.system(" ifconfig wlan1 up 192.168.0.1 netmask 255.255.255.0")
    os.system(" route add -net 192.168.0.0 netmask 255.255.255.0 gw 192.168.0.1")
    os.system(" ip link set wlan1 up")

    # Clear all IP Rules
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')

    # Redirect any request to the captive portal
    os.system(
        f'iptables -t nat -A PREROUTING  -i usb0 -p tcp --dport 80 -j DNAT  --to-destination 192.168.0.1:80')
    os.system(
        f'iptables -t nat -A PREROUTING  -i usb0 -p tcp --dport 443 -j DNAT  --to-destination 192.168.0.1:80')

    # os.system("systemctl stop systemd-resolved")
    os.system("iptables --table nat --append POSTROUTING --out-interface wlp2s0 -j MASQUERADE")
    os.system("iptables --append FORWARD --in-interface wlan1 -j ACCEPT")
    DNSmasq()
    hostapd("ben")
    conf_apache2()
    os.system("sysctl net.ipv4.ip_forward=1")
    os.system("systemctl stop systemd-resolved")
    os.system(" ip link set wlan1 up")

    # os.system("sudo hostapd hostapd.conf ")
    # os.system("dnsmasq -C dnsmasq.conf -d")
