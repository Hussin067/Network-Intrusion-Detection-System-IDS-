import time
from logger import read_logs , LOG_FILE
last_size = 0
while True:
    current_size = 0

    try:
        current_size = LOG_FILE.stat().st_size
    except FileNotFoundError:
        pass
    if current_size > last_size:
        tcp_scan = 0
        udp_flood = 0
        icmp_flood = 0
        test_alert = 0

        lines = read_logs()

        print("\033[2J\033[H")

        for line in lines:
            if "TCP Port Scan" in line:
                tcp_scan += 1
            elif "UDP FLOOD" in line:
                udp_flood += 1
            elif "ICMP FLOOD" in line:
                icmp_flood += 1
            elif "TEST ALERT" in line:
                test_alert +=1

        total_alert = tcp_scan + udp_flood + icmp_flood + test_alert

        print("===============================")
        print("           IDS Dashboard       ")
        print("===============================")
        print()
        print("Total alert: ",total_alert)
        print()
        print("TCP port scann: ",tcp_scan)
        print("UDP Flood: ",udp_flood)
        print("ICMP Flood: ",icmp_flood)
        print("TEST alert: ",test_alert)
        print()
        print("===============================")
        print("         Recent Alerts         ")
        print("===============================")

        for line in lines:
            print(line.strip())
    time.sleep(1)

