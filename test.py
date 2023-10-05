##
# @file test.py
#
# @brief Testovací script pre dhcp analyzátor dhcp-stats
#
# @author Matej Keznikl

from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
import time

def send_dhcp_discover(client_mac):
    eth_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac)
    ip_discover = IP(src="0.0.0.0", dst="255.255.255.255")
    udp_discover = UDP(sport=68, dport=67)
    bootp_discover = BOOTP(chaddr=client_mac, ciaddr="0.0.0.0", flags=0x8000)
    dhcp_options_discover = [
        ("message-type", "discover"),
    ]
    dhcp_discover = DHCP(
        options=[
            (option, value) if value else (option,)
            for option, value in dhcp_options_discover
        ]
    )

    packet_discover = (
        eth_discover / ip_discover / udp_discover / bootp_discover / dhcp_discover
    )
    sendp(packet_discover, iface="enp0s3")


def send_dhcp_offer(client_mac, offered_ip, server_ip):
    eth_offer = Ether(dst=client_mac)
    ip_offer = IP(src=server_ip, dst="255.255.255.255")
    udp_offer = UDP(sport=67, dport=68)
    bootp_offer = BOOTP(op=2, chaddr=client_mac, yiaddr=offered_ip)
    dhcp_options_offer = [
        ("message-type", "offer"),
        ("server_id", server_ip),
        ("lease_time", 43200),
        ("subnet_mask", "255.255.255.0"),
        ("router", server_ip),
    ]
    dhcp_offer = DHCP(
        options=[
            (option, value) if value else (option,)
            for option, value in dhcp_options_offer
        ]
    )

    packet_offer = eth_offer / ip_offer / udp_offer / bootp_offer / dhcp_offer
    sendp(packet_offer, iface="enp0s3")


def send_dhcp_request(client_mac, offered_ip):
    eth_request = Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac)
    ip_request = IP(src="0.0.0.0", dst="255.255.255.255")
    udp_request = UDP(sport=68, dport=67)
    bootp_request = BOOTP(
        chaddr=client_mac, ciaddr="0.0.0.0", flags=0x8000, yiaddr=offered_ip
    )
    dhcp_options_request = [
        ("message-type", "request"),
        ("requested_addr", offered_ip),
    ]
    dhcp_request = DHCP(
        options=[
            (option, value) if value else (option,)
            for option, value in dhcp_options_request
        ]
    )

    packet_request = (
        eth_request / ip_request / udp_request / bootp_request / dhcp_request
    )
    sendp(packet_request, iface="enp0s3")


def send_dhcp_ack(client_mac, ack_ip, server_ip):
    eth_ack = Ether(dst=client_mac)
    ip_ack = IP(src=server_ip, dst="255.255.255.255")
    udp_ack = UDP(sport=67, dport=68)
    bootp_ack = BOOTP(op=2, chaddr=client_mac, yiaddr=ack_ip)
    dhcp_options_ack = [
        ("message-type", "ack"),
        ("server_id", server_ip),
        ("lease_time", 43200),
        ("subnet_mask", "255.255.255.0"),
        ("router", server_ip),
    ]
    dhcp_ack = DHCP(
        options=[
            (option, value) if value else (option,)
            for option, value in dhcp_options_ack
        ]
    )

    packet_ack = eth_ack / ip_ack / udp_ack / bootp_ack / dhcp_ack
    sendp(packet_ack, iface="enp0s3")


client_mac_address = "00:11:22:33:44:55"
server_ip_address = "10.0.2.2"
offered_ip_address = "10.0.2.4"
acknowledged_ip_address = "10.0.2.4"

# DHCP Discover
send_dhcp_discover(client_mac_address)
print("Discovery packet sent")
time.sleep(2)  # Čakanie 2 sekundy

# # DHCP Offer
send_dhcp_offer(client_mac_address, offered_ip_address, server_ip_address)
print("Offer packet sent")
time.sleep(2)  # Čakanie 2 sekundy

# DHCP Request
send_dhcp_request(client_mac_address, offered_ip_address)
print("Request packet sent")
time.sleep(2)  # Čakanie 2 sekundy

# # DHCP Acknowledge
send_dhcp_ack(client_mac_address, acknowledged_ip_address, server_ip_address)
print("Acknowledge packet sent")
