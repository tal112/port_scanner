import eel
import nmap
from datetime import datetime
import re
import sys
import pandas as pd
import socket
import Port
import json


print("#"*100)
print("     Author: Tal Sperling")
print("     This code is to be used for educational purposes or legal penetration testing only")
print("     I do not take responsibility for any misuse or illegal action/use of this code")
print("#"*100+"\n")


@eel.expose
def validate_input(input_value):

    ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

    if input_value == "":
        response = '{"success":"false", "msg":"Please enter a value"}'
    elif ip_add_pattern.search(input_value):
        ip_address = input_value
        response = '{"success":"true", "msg":"I.P. address confirmed", "response":"' + ip_address + '"}'
    else:
        try:
            host_ip_address = socket.gethostbyname(input_value)
            ip_address = host_ip_address
            response = '{"success":"true", "msg":"URL confirmed", "response":"' + ip_address + '"}'
        except:
            response = '{"success":"false", "msg":"Invalid"}'

    return response

@eel.expose
def start_scan(ip_address, low_port, high_port, ports_range, is_csv):
    print("start scan")
    ports_list = []
    ports_json = []
    nm = nmap.PortScanner()

    response = ""

    if ports_range == "popular":
        response = popular_ports(ports_list, ports_json, nm, ip_address, is_csv)
    else:
        response = chosen_ports_and_all(ports_list, ports_json, nm, ip_address, low_port, high_port, ports_range, is_csv)

    return response

def popular_ports(ports_list, ports_json, nm, ip_address, is_csv):
    ports_to_scan = [20,21,22,23,25,50,51,53,67,68,69,80,110,119,123,135,136,137,138,139,143,161,162,389,443,989,990,3389]

    start_time = datetime.now()
    print("Scanning...")

    for port in ports_to_scan:
        nm.scan(ip_address, str(port))
        open_port = nm[ip_address].has_tcp(port)
        if open_port:
            state = nm[ip_address]['tcp'][port]["state"]

            if state == "open":
                name = nm[ip_address]['tcp'][port]["name"]
                product = nm[ip_address]['tcp'][port]["product"]
                version = nm[ip_address]['tcp'][port]["version"]
                info = nm[ip_address]['tcp'][port]["extrainfo"]

                port_data = Port.Port(ip_address, port, state, name, product, version, info)
                ports_list.append(port_data)
                ports_json.append(port_data.toJSON())

    df = pd.DataFrame([t.__dict__ for t in ports_list])

    if is_csv:
        export_csv(df, ip_address)

    end_time = datetime.now()
    scan_time = (end_time - start_time).total_seconds() / 60.0

    print(ports_json)
    return json.dumps(ports_json)


def chosen_ports_and_all(ports_list, ports_json, nm, ip_address, low_port, high_port, ports_range, is_csv):

    if ports_range == "all":
        ports_to_scan = "1" + "-" + "65535"
    else:
        ports_to_scan = low_port + "-" + high_port

    start_time = datetime.now()
    print("Scanning...")
    nm.scan(ip_address, ports_to_scan)

    for num in range(int(high_port)):
        open_port = nm[ip_address].has_tcp(int(num))
        #  print(open_port)
        if open_port:
            state = nm[ip_address]['tcp'][int(num)]["state"]

            if state == "open":
                name = nm[ip_address]['tcp'][int(num)]["name"]
                product = nm[ip_address]['tcp'][int(num)]["product"]
                version = nm[ip_address]['tcp'][int(num)]["version"]
                info = nm[ip_address]['tcp'][int(num)]["extrainfo"]

                port_data = Port.Port(ip_address, num, state, name, product, version, info)
                ports_list.append(port_data)
                ports_json.append(port_data.toJSON())

    df = pd.DataFrame([t.__dict__ for t in ports_list])

    if is_csv:
        export_csv(df, ip_address)



    end_time = datetime.now()
    scan_time = (end_time - start_time).total_seconds() / 60.0

    print(ports_json)
    return json.dumps(ports_json)



def export_csv(df, ip_address):
    try:
        df.to_csv(ip_address + '.csv')
    except:
        print("Export to csv... permission denied. Check if the file is opened?")

eel.init('web')

try:
    eel.start('index.html', size=(2000, 2500), port=0)  # python will select free ephemeral ports.

    eel.get_ready()()
except (SystemExit, MemoryError, KeyboardInterrupt):
    print("Good Bye")