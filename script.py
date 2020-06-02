#!/bin/python

#=============imports=============#
import requests
import re as regex

#=============functions=============#
def catchips():
    aux = open('ips.txt', 'r').readlines()

    ips = []#list of ips
    ips_unique = []#list of ordened unique ips

    for each in aux:#adding every ips in the array
        ips.append(each.strip().split('.'))#splitted in 4 octets

    ips.sort(key=last)#sort the list of ips

    for i in ips:
        aux = '.'.join(i)#auxiliary variable
        if aux not in ips_unique:#if the current ip not in the new array, append it
            ips_unique.append(aux)#add in new array
    
    return ips_unique

def last(e):#function that return a last octect as key to sort function
    return int(e[:][3])

def mask(ip, netmask):
    #Parameters are sended by url (GET)
    url = 'http://jodies.de/ipcalc?host={}&mask1={}&mask2='.format(ip, netmask)
    resp = requests.get(url)

    #find a touple (name, ip) -> (netmask, 255.255.255.0)
    re = r'(\w+/?\w+):\s+</font><font color=\"#0000ff\">(\d+\.\d+\.\d+\.\d+\s=\s\d+|\d+\.?\d+\.\d+\.\d+/?\d?\d?|\d+)'
    data = regex.findall(re, resp.text)

    return data

def verbroad(network, broadcast, ips_unique):
    #check if the network and broadcast address is in list ip
    n = b = False
    if network in ips_unique:
        n = True
    if broadcast in ips_unique:
        b = True

    return (n,b)

def verify(minhost, maxhost, ips_unique):
    aux = []
    for each in ips_unique:#for each ip
        each = each.split('.')
        #compare if the last octect is lower then other
        if int(each[3]) >= int(minhost.split('.')[3]) and int(each[3]) <= int(maxhost.split('.')[3]):
            aux.append('.'.join(each))
        #if the ip is in interval appends it
        elif int(each[3]) > int(minhost.split('.')[3]):
            #if not, we can break.. because the array are ordened, and dont have more values that we are able to append
            break
    return aux

class ip():
    def __init__(self, address, netmask):
        self.address = address
        self.netmask = netmask

#=============main=============#
ips = catchips()
finished = []

for each in ips:
    #control variables
    netmask = 32
    last_nhost = 0

    #the range of netmasks ([27, 32[)
    for i in range(27, 33):
        data        = mask(each, i)
        address     = data[0][1]
        network     = data[3][1].split('/')[0]
        broadcast   = data[4][1]
        minhost     = data[5][1]
        maxhost     = data[6][1]
        numhost     = int(data[7][1])

        #verify if the network or broadcast is in list of ip
        n, b = verbroad(network, broadcast, ips)
        #verify the amount of ips that we have in the netmask interval
        ips_in_range = verify(minhost, maxhost, ips)
        rg = len(ips_in_range)
        
        #if the ip in the /27 network and ip are equals, all the nexts netmaks will be.. then we can set loopback (/32)
        if i == 27 and (network == address or rg == 1):
            netmask = 32
            break
        
        #if the network or broadcast ip of this netmask is in the ip list, we can't use that, then... continue in the next
        if n or b:
            continue

        #if the last number of hosts in the netmask interval are bigger then current, we can set the past how netmask
        #because in this way we got more agroupments but at cost of IP waste
        if last_nhost > rg:
            netmask = i-1
            break
        
        #
        if rg == 1 or rg == 0:
            netmask = 32
            break

        last_nhost = rg
        netmask = i 

    finished.append(ip(address, netmask))

for each in finished:
    print "{}/{}\n".format(each.address, str(each.netmask))