import os

if __name__=='__main__':
    os.system('rfkill unblock all')
    os.system('service NetworkManager start')
    os.system('iptables -F')
    os.system('iptables -t nat -F')
    #os.system("sudo rm -f build/hostapd.conf")
    #os.system("sudo rm -f build/dnsmasq.conf")
    #os.system("rm -rf build/")
    os.system("sudo systemctl unmask systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl enable systemd-resolved >/dev/null 2>&1")
    os.system("sudo systemctl start systemd-resolved >/dev/null 2>&1")
    #os.system("sudo rm /etc/resolv.conf")
    #os.system("sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf")

