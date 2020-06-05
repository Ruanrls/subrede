#!/bin/python

#   IMPORTANT MODULES
try:
    import requests
    import argparse
    import re as regex
    from time import sleep
    import os
except Exception as error:
    err(str(error))

#   ARGUMENT PARSES
try:
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Path to file with the list of IPS', required=True)
    parser.add_argument('-o', '--output', help='Path of file to output', action='store', default=None)
    parser.add_argument('-v', '--verbose', help='Increase the verbosity of program', action='store_true')
    parser.add_argument('-so', '--separatedOutput', help='Makes an output separated in 3 archives', action='store_true', dest='so')

    args = parser.parse_args()

    if args.so == True and args.output == None:
        print "You need to set the path where output will be saved with -o (do not include the name of files)"
        exit(0)

except Exception as error:
    err(str(error))

#   READ FILE OF IPS AND RETURN THE ARRAY CONTAINING THE IPS WHITOUT \n
def catchip(path):
    ips = []
    with open(path, 'r') as file:
        for ip in file:
            ips.append(ip.strip())
    
    return ips

#TO ORDENE THE LIST OF IPS, WE NEED TO COMPARE THE LAST OCTECT  AND REMOVE THE DUPLICATES
def ordene(ips):
    def split(octect):
        return int(octect.split('.')[3])# this    each.split('.')[3]   return  192.168.0.100 -> (100)

    ip = set(ips)
    return sorted(ip, key=split)

#CALCULATE THE INFORMATIONS OF IP, FILTER THAT RESPONSE AND RETURN
def calculate(ip, netmask):

    def filter(data):
        re = r'(\w+/?\w+):\s+</font><font color=\"#0000ff\">(\d+\.\d+\.\d+\.\d+\s=\s\d+|\d+\.?\d+\.\d+\.\d+/?\d?\d?|\d+)'
        data = regex.findall(re, data)

        return dict(data)

    url = 'http://jodies.de/ipcalc'
    payload = {
        'host':ip,
        'mask1':netmask,
        'mask2':''
    }
    data = requests.get(url, params=payload)

    return filter(data.text)

#VERIFY IF ALREADY HAVE THIS IP WITH THIS NETMASK IN THE VERIFIED LIST OF IPS
def verbroad(ip):
    global ips_to_verify

    if ip in ips_to_verify:
        return True
    else:
        return False

#CLASS THAT DEFINE WHAT IS IP
class ipform():
    def __init__(self, ip, netmask, broadcast, network):
        self.ip = ip
        self.netmask = netmask
        self.broadcast = broadcast
        self.network = network

#RETURN A LIST WITH THE HOSTS THAT CAN BE IN THE NETMASK OF THE CURRENT IP 
def interval(minhost, maxhost, ips):
    aux = []
    for ip in ips:
        if minhost.split('.')[3] <= ip.split('.')[3] <= maxhost.split('.')[3]:
           aux.append(ip) 
        elif minhost.split('.')[3] > maxhost.split('.')[3]:
            break

    return aux

#VERIFY IF THE IP HAVE ITSELF AS BROADCAST OR NETWORK (RETURN A TOUPLE WITH F OR T)
def selfbroad(address, netmask, broadcast, network):
    b = n = False

    if address+'/'+str(netmask) == network:
        n = True
    
    if address == broadcast:
        b = True
    
    return (n, b)

#adds the ips that pass every condition into the correct list
def verified(ip, netmask, broadcast, network):
    global ips_to_verify
    global ip_verified

    ips_to_verify.append(ip+'/'+str(netmask))
    ip_verified.append(ipform(ip, netmask, broadcast, network))

def err(string):
    print "Error on module:\n[-] {}".format(string)


def output(path):
    global ip_verified
    try:

        with open(path, 'a') as file:
            for each in ip_verified:
                file.write("Address:\t{}/{}\tNetwork:\t{}\tBroadcast:\t{}\n".format(each.ip, each.netmask, each.network, each.broadcast))
        
        print "Output saved in: {}".format(path)
    except Exception as error:
        err(error)
        printing()

def separated(path):
    global ip_verified

    try:
        with open(path+'/addresses.txt', 'a') as file:
            for each in ip_verified:
                file.write("{}/{}\n".format(each.ip, each.netmask))

        with open(path+'/broadcast.txt', 'a') as file:
            for each in ip_verified:
                file.write("{}\n".format(each.broadcast))

        with open(path+'/network.txt', 'a') as file:
            for each in ip_verified:
                file.write("{}\n".format(each.network))

        print "\nOutput saved in {} names: addresses.txt, broadcast.txt, network.txt\n".format(path)
    except Exception as error:
        err(str(error))
        print "Printing"
        printing()

def printing():
    global ip_verified

    for each in ip_verified:
        print "\tAddress:\t{}/{}\tNetwork:\t{}\tBroadcast:\t{}".format(each.ip, each.netmask, each.network, each.broadcast)
#MAIN

print "Running..."
ip_verified = []
ips = ordene(catchip(args.file))#RETURN THE LIST OF IPS IN THIS PATH FILE
ips_to_verify = []

for ip in ips:
    netmask = 27

    l_nhost = []
    l_broadcast = ''
    l_network = ''

    while True:
        data = calculate(ip, netmask)#calculate the subnet in this current netmask
        n, b = selfbroad(ip, netmask, data['Broadcast'], data['Network'])#verify if the ip haves itself as a broadcast or network

        if verbroad(ip):
            l_nhost = []
            netmask += 1
            continue

        #IF THE CURRENT IP HAVE ITSELF AS A BROADCAST OR NETWORK, THE MASK NEEDS TO BE /32 
        if n or b:
            netmask = 32
            verified(ip, netmask, ip, ip+'/'+str(netmask))
            break
        
        nhosts = interval(data['HostMin'], data['HostMax'], ips)
        if len(nhosts) < len(l_nhost):
            netmask -= 1
            verified(ip, netmask, l_broadcast, l_network)
            break

        if netmask == 32:
            verified(ip, netmask, ip, ip+'/'+str(netmask))
            break

        l_nhost = nhosts
        l_broadcast = data['Broadcast']
        l_network = data['Network']
        netmask += 1

if args.output == None:
    printing()
else:
    if args.so == True:
        separated(args.output)
    else:
        output(args.output)

    if args.verbose == True:
        printing()
    print "Finished..."