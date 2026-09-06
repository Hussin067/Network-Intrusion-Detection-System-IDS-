from scapy.all import sniff, IP , TCP , UDP , ICMP
import time
from datetime import datetime

scanned_ports = {}
tcp_alerted = set()
icmp_tracker = {}
icmp_alerted = set()
udp_tracker = {}
udp_alerted = set()

def alert(alert_type , source , destination  , details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print()
    print("==============================")
    print("           IDS Alert          ")
    print("==============================")
    print("Type: ", alert_type)
    print("source: " , source)
    print("Destination: " ,destination)
    print("Details: " , details)
    print("==============================")
    print()

    with open("LOG_FILE", "a") as log_file:
        log_file.write(
            f"{timestamp} | {alert_type} | "
            f"Source: {source} | Destination: {destination} | "
            f"{details}\n"
        )
    


def packet_callback(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        print("Source: ",source)
        print("destination: ", destination)
        
    if TCP in packet:
        TcpSourcePort = packet[TCP].sport
        TcpDestinationPort = packet[TCP].dport
        TcpFlags = packet[TCP].flags
        print("Protocol: TCP")
        print("Source port: ", TcpSourcePort)
        print("destination Port: ", TcpDestinationPort)
        print("TCP Flag: " , TcpFlags)
        if packet[TCP].flags == "S":
            current_time = time.time()
            if source not in scanned_ports:
                scanned_ports[source] = {}
            scanned_ports[source][packet[TCP].dport] = current_time
            for port in list(scanned_ports[source]):
                if current_time - scanned_ports[source][port] > 10:
                    del scanned_ports[source][port]
            if len(scanned_ports[source]) >= 5 and source not in tcp_alerted:                     
                alert(
                    "TCP Port Scan",
                    source,
                    destination,
                    f'Ports scanned: {list(scanned_ports[source].keys())}'
                )
                tcp_alerted.add(source)


    elif UDP in packet:
        UdpSourcePort = packet[UDP].sport
        UdpDestinationPort = packet[UDP].dport
        print("Protocol: UDP")
        print("Source port: ",UdpSourcePort)
        print("Destenation port: ",UdpDestinationPort)

        source = packet[IP].src
        current_time = time.time()
        if source not in udp_tracker:
            udp_tracker[source] = {
                "Start_time": current_time,
                "count":1
            }
        else:
            elapsed_time = current_time - udp_tracker[source]["Start_time"]

            if elapsed_time > 10:
                udp_tracker[source] = {
                    "Start_time":current_time,
                    "count":1
                }
            else:
                udp_tracker[source]["count"] +=1
        elapsed_time = current_time - udp_tracker[source]["Start_time"]
        if (
            elapsed_time <= 10 
            and udp_tracker[source]["count"] >= 50
            and source not in udp_alerted
        ):
            alert(
                "UDP FLOOD",
                source,
                packet[IP].dst,
                f'{udp_tracker[source]["count"]} packets in {round (elapsed_time , 2)} seconds'
            )
            udp_alerted.add(source)

    elif ICMP in packet:
        IcmpType = packet[ICMP].type
        IcmpCode = packet[ICMP].code
        print("protocol: ICMP")
        print("ICMP type: ", IcmpType)
        print("ICMP code: ",IcmpCode)
        if IP in packet:
            source = packet[IP].src
            current_time = time.time()
            if source not in icmp_tracker:
                icmp_tracker[source] = {
                    "Start_time": current_time , 
                    "count": 1
                }
            else:
                elapsed_time = current_time - icmp_tracker[source]["Start_time"]
                if elapsed_time > 10:
                    icmp_tracker[source] = {
                        "Start_time": current_time,
                        "count": 1
                    }
                else:
                    icmp_tracker[source]["count"] += 1
            elapsed_time = current_time - icmp_tracker[source]["Start_time"]

            if (
                elapsed_time <= 10 
                and icmp_tracker[source]["count"] >= 20
                and source not in icmp_alerted):
                alert (
                    "ICMP FLOOD" , 
                    source,
                    destination,
                    f'{icmp_tracker[source]["count"]} packets in {round (elapsed_time , 2)} seconds'
                )
                icmp_alerted.add(source)


            
    print()

sniff(iface="eth1", prn=packet_callback, filter="ip")

