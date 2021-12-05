class Port:
    def __init__(self, port, state, name, product, version, info):
        self.port = port
        self.state = state
        self.name = name
        self.product = product
        self.version = version
        self.info = info




import nmap
from datetime import datetime
import re
import sys
import pandas as pd
import socket


print("#"*100)
print("     Author: Tal Sperling")
print("     This code is to be used for educational purposes or legal penetration testing only")
print("     I do not take responsibility for any misuse or illegal action/use of this code")
print("#"*100+"\n")


ports_list = []
nm = nmap.PortScanner()

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

while True:
    input_value = input("Enter I.P. address or URL to scan(type exit to quit): ")

    if ip_add_pattern.search(input_value):
        ip_address = input_value
        print("I.P. address confirmed")
        break
    elif input_value == "exit":
        print("Good-bye!")
        sys.exit()
    else:
        #print("I.P. address is not valid")
        try:
            host_ip_address = socket.gethostbyname(input_value)
            ip_address = host_ip_address
            break
        except:
            print("Invalid input")


    print("")

print("")

low_port = input("Enter low port number: ")
high_port = input("Enter high port number: ")



ports_to_scan = low_port+"-"+high_port

start_time = datetime.now()
print("Scanning...")
nm.scan(ip_address, ports_to_scan)

for num in range(int(high_port)):
    open_port = nm[ip_address].has_tcp(int(num))
    if open_port:
        state = nm[ip_address]['tcp'][int(num)]["state"]
        name =nm[ip_address]['tcp'][int(num)]["name"]
        product = nm[ip_address]['tcp'][int(num)]["product"]
        version = nm[ip_address]['tcp'][int(num)]["version"]
        info =nm[ip_address]['tcp'][int(num)]["extrainfo"]

        port_data = Port(num, state, name, product, version, info)
        ports_list.append(port_data)

for port in ports_list:
    print("Port: {}".format(port.port))
    print("state: {}".format(port.state))
    print("name: {}".format(port.name))
    print("product: {}".format(port.product))
    print("version: {}".format(port.version))
    print("info: {}".format(port.info))

print("_______________")

df = pd.DataFrame([t.__dict__ for t in ports_list ])

try:
    df.to_csv(input_value + '.csv')
except:
    print("Export to csv... permission denied. Check if the file is opened?")

end_time = datetime.now()
scan_time = (end_time - start_time).total_seconds() / 60.0
print("Scan Time: {}".format(scan_time))




