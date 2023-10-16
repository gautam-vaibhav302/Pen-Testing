import nmap
scanner = nmap.PortScanner()
print ("\tWelcome to the NMAP Port-Scanning tool! \n")
print("\n<---------------------------------------------------------->\n")

ip_addr = input("\nEnter the ip address that you want to scan : ")
print("\nThe IP address that you have entered is : ", ip_addr)

res = int(input('''\nEnter the type of scan you want to run :-
                1) SYN ACK scan
                2) UDP scan
                3) Comprehensive scan
 : '''))

if res == 1 :
    print("\nNMAP version : ",scanner.nmap_version(),)
    scanner.scan(ip_addr, '1-1000', '-v -sS')
    print(scanner.scaninfo())
    print("IP status : ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports : ", scanner[ip_addr]['tcp'].keys())

elif res == 2 : 
    print("\nNMAP version : ",scanner.nmap_version(),)
    scanner.scan(ip_addr, '1-100', '-v -sU')
    print(scanner.scaninfo())
    print("IP status : ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports : ", scanner[ip_addr]['udp'].keys())

elif res == 3 : 
    print("\nNMAP version : ",scanner.nmap_version(),)
    scanner.scan(ip_addr, '1-100', '-v -sS -sV -A -O')
    print(scanner.scaninfo())
    print("IP status : ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports : ", scanner[ip_addr]['tcp'].keys())
    print("Hostname : ",scanner[ip_addr].hostname())

else :
    print("\n\tENTER A VALID RESPONSE !!!\n")