#!/usr/bin/python3

# bsFalcon.py
# Created by Emrecan ÖKSÜM at 15.08.2020
# Beetware Stream Falcon
# Watch the connections stream, check ip addresses against abusive usage and ban if IP is either Proxy or VPN.

# Open sourced at 17.10.2020 due to better version being developed currently.
# It is a known fact that this code is not sufficient for the cause. It's primitive, inefficient and slow. It is open sourced for education purposes.
# However, it can help websites mitigate small sized Layer7 HTTP Flood typed attacks.

import os
import sys
import requests
import datetime
import socket
import random
import json
import time

__version__ = "2.3"
__vname__ = "Beta"

def loadDatabase(action, ip):
    if not os.path.exists("/usr/local/beetware/Falcon.db"):
        os.system("touch /usr/local/beetware/Falcon.db")
    
    if ip != 2:
        ip = ip.strip()
    
    if action == "DELETE":
        handle = open("/usr/local/beetware/Falcon.db", "r")
        dbl = handle.read()
        handle.close()
        dbl = dbl.strip()
        try:
            dbl = json.loads(dbl)
        except:
            print("[!] Falcon.db isn't stable! Recreating...")
            dbl = []
        
        ndbl = dbl.copy()
        
        for ind, rule in enumerate(dbl):
            if rule['ip'] == ip:
                del ndbl[ind]
        ndbl = json.dumps(ndbl)
        handle = open("/usr/local/beetware/Falcon.db","w")
        handle.write(ndbl)
        handle.close()
        return 1
    elif action == "INSERT":
        dbhandle = os.popen("grep \"" + ip + "\" /usr/local/beetware/Falcon.db")
        line = dbhandle.read()
        
        if line.find(ip) != -1:
            return 1
        
        handle = open("/usr/local/beetware/Falcon.db","r")
        dbl = handle.read()
        handle.close()
        
        ctime = time.time()
        ctime = ctime + 10800 #3 hrs
        
        dbl = dbl.strip()
        try:
            dbl = json.loads(dbl)
        except:
            dbl = []
        dbl.append({"expire":str(ctime), "ip":ip})
        dbl = json.dumps(dbl)
        handle = open("/usr/local/beetware/Falcon.db","w")
        handle.write(dbl)
        handle.close()
        return 1
    elif action == "SELECT":
        handle = open("/usr/local/beetware/Falcon.db","r")
        dbl = handle.read()
        handle.close()
        dbl = dbl.strip()
        try:
            dbl = json.loads(dbl)
        except:
            dbl = []
        ret = {}
        if ip == 2:
            ret = dbl
        else:
            for ind, rule in enumerate(dbl):
                if rule['ip'] == ip:
                    ret = rule
                    break
        return ret
    else:
        return 0

def unblockIp(ip):
    dbhandle = os.popen("grep \"" + ip + "\" /usr/local/beetware/Falcon.db")
    line = dbhandle.read()
    
    if line.find(ip) == -1:
        return 1
    
    #fwhandle = os.popen("/sbin/iptables -t mangle -D PREROUTING -s " + ip + "/32 -j DROP")
    fwhandle = os.popen("/sbin/iptables -D INPUT -s " + ip + "/32 -j REJECT")
    fwhandle.read()
    handle = os.popen("/sbin/iptables-save")
    handle.read()
    loadDatabase("DELETE", ip)
    return 1
    
def getSocketList(ip):
    iplist = []
    hd = os.popen("ss 2>&1 | grep " + ip)
    lines = hd.read()
    lines = lines.split("\n")
    for line in lines:
        if line == "":
            continue
        line = line.split("                                    ")
        try:
            iplist.append(line[1].strip())
        except:
            continue
    return iplist

def killSocket(ip):
    cmd = os.popen("ss -K dst " + ip)
    cmd.read()
    #sl = getSocketList(ip)
    #for sck in sl:
    #    hd = os.popen("killcx " + sck + " lo")
    #    hd.read()

def blockIp(ip):
    #hd = os.popen("/sbin/iptables -t mangle -I PREROUTING -s " + ip + " -j DROP")
    hd = os.popen("/sbin/iptables-save")
    ipts = hd.read()
    if ipts.find(ip) == -1:
        #hd = os.popen("/sbin/iptables -I INPUT -i eth0 -s " + ip + "/32 -j REJECT")
        hd = os.popen("/sbin/iptables -I INPUT -s " + ip + "/32 -j REJECT")
        #hd = os.popen("/sbin/iptables -t mangle -I PREROUTING -i eth0 -s " + ip + " -j DROP")
        hd.read()
        hd = os.popen("/sbin/iptables-save")
        hd.read()
        loadDatabase("INSERT", ip)
    killSocket(ip)
    

def autoPardon():
    print("[i] Starting auto-pardon")
    recs = loadDatabase("SELECT", 2)
    for rec in recs:
        if float(rec['expire']) < time.time():
            print("[i] IP Ban of " + rec['ip'] + " expired. Unbanning...")
            unblockIp(rec['ip'])
    print("[i] Done auto-pardon")
    return 1

def scr(orig):
    dest = orig[:]
    random.shuffle(dest)
    return dest

def cIpList(line):
    
    try:
        line = line.strip()
        line = line.split(" ")
        line = line[1]
    except:
        return 0
    
    try:
        socket.inet_aton(line)
    except socket.error:
        return 0
    return line

def getIPInfo(ip):
    
    print("[i] Initiating lookup for IP: " + ip + " address...")
    bintel = requests.post("[!!!] REDACTED IP INTEL API URL [!!!]", data={"ip":ip})
    bintel = bintel.text
    
    try:
        bintel = json.loads(bintel)
    except:
        time.sleep(5)
        bintel = requests.post("[!!!] REDACTED IP INTEL API URL [!!!]", data={"ip":ip})
        bintel = bintel.text
        bintel = json.loads(bintel)
    
    return bintel

def chkWhitelist(ip):
    
    wf = open("/usr/local/beetware/whitelist","r")
    whitelist = wf.readlines()
    del whitelist[0]
    wf.close()
    if ip + "\n" in whitelist:
        return 1
    return 0

def checkDns(ip):
    
    dnsip = ["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4"]
    if ip in dnsip:
        return 1
    return 0

def getRdns(ip):
    
    try:
        rtup = socket.getnameinfo((ip, 0), 0)[0]
    except:
        rtup = "none"
    
    if not rtup:
        rtup = "none"
    
    return rtup

def bootedEpoch():
    return time.time() - psutil.boot_time()

def chkIP(ip):
    
    if ip == "127.0.0.1":
        print("[+] That's me!")
        return 0
    
    if ip == "185.0.0.0":
        print("[+] That's my public address!")
        return 0
    
    if ip.find("10.0.0") != -1:
        print("[+] Found Beetware Remote Network IP: " + ip + " not a threat.")
        return 0
    
    if checkDns(ip):
        print("[+] Found DNS server! not a threat.")
        return 0
    
    if chkWhitelist(ip):
        print("[+] IP Address " + ip + " is not identified as a threat by local whitelist.")
        return 0
    
    ipintel = getIPInfo(ip)
    rdns = getRdns(ip)
    
    if rdns != "none" and (rdns.find("google.com") != -1 or rdns.find("googlebot.com") != -1 or rdns.find("yandex.ru") != -1 or rdns.find("yandex.com") != -1 or rdns.find("search.msn.com") != -1 or rdns.find("yahoo.net") != -1 or rdns.find("duckduckgo.com") != -1):
        try:    
            dnsip = socket.gethostbyname(rdns)
        except:
            print("[!] Failed to resolve " + rdns + " to a valid IP address!")
            dnsip = "none"
        if dnsip == ip:
            print("[+] Found a SEO spider bot! Information: " + rdns + " to IP: " + dnsip)
            return 0
    
    if ipintel['is_whitelisted']:
        print("[+] IP Address " + ip + " is not identified as a threat by remote whitelist.")
        return 0
    
    if ipintel['is_tor'] or ipintel['is_tor_exit']:
        return 1
    
    if ipintel['is_cloud_provider']:
        return 1
        
    if ipintel['is_tor'] or ipintel['is_tor_exit']:
        return 1
    
    if ipintel['is_proxy']:
        return 1
    
    if ipintel['is_abuser']:
        return 1
    
    if ipintel['is_attacker']:
        return 1
    
    print("[+] IP Address " + ip + " is not identified as a threat by IP intelligence.")
    return 0

if os.path.exists("/usr/local/beetware/bsFalcon/bsFalcon.pid"):
    pf = open("/usr/local/beetware/bsFalcon/bsFalcon.pid","r")
    rpid = pf.read()
    pf.close()
    
    stream = os.popen("ps aux | grep " + rpid + " | grep bsFalcon | grep -v grep")
    output = stream.read()
    
    if output.find("bsFalcon") == -1:
        print("bsFalcon pidfile exists but process seems to be dead. Unlinking the pidfile and starting over...")
        os.unlink("/usr/local/beetware/bsFalcon/bsFalcon.pid")
        sys.exit()
    
    print("ERROR! Failed to start Beetware Stream Falcon. Daemon is already running!")
    sys.exit()

pid = str(os.getpid())

f = open("/usr/local/beetware/bsFalcon/bsFalcon.pid", 'w')
f.write(pid)
f.close()

while os.path.exists("/usr/local/beetware/bsFalcon/bsFalcon.pid") and os.path.exists("/usr/local/beetware/fwdcmd"):
    
    print("Starting Beetware Stream Auditor Falcon " + __version__ + " Beta ...")
    
    now = datetime.datetime.now()
    if now.minute == 0:
        autoPardon()
    
    hd = os.popen("netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | wc -l")
    cc = hd.read()
    
    cc = cc.strip()
    cc = int(cc)
    
    if cc > 5:
        #print("[!] PANIC! CPU usage is higher than %15! Invoke bsFalcon...")
        print("[!] More then 5 connections are open! Invoke bsFalcon...")
    else:
        #print("[i] CPU usage is stable. No need to invoke bsFalcon.")
        print("[i] Connection count is normal. No need to invoke bsFalcon.")
        break
    
    stream = ""
    output = ""
    
    stream = os.popen("netstat -ntu | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr")
    output = stream.read()
    
    output = output.split("\n")
    
    iplist = []
    
    print("### PARSING ACTIVE CONNECTIONS ###")
    for line in output:
        ip = cIpList(line)
        if ip:
            iplist.append(ip)
    #iplist = scr(iplist) this is stupid
    print("### CONDUCTING IP INTELLIGENCE TEST ###")
    for ip in iplist:
        if chkIP(ip):
            print("[!] Closing socket and blocking IP " + ip + " due to threat risk.")
            blockIp(ip)
    print("Done! Go to next iteration...")

print("Ending! Bye Bye!")
os.unlink("/usr/local/beetware/bsFalcon/bsFalcon.pid")
