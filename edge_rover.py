# Author : Haytham Taymour
# Email  : haytham.taymour@gmail.com
import paramiko
import time
#import re
#from docx import Document
import os
import sys
import subprocess
from getpass import getpass
from datetime import datetime

paramiko.util.log_to_file("connection.log")
print ("Edge rover SDWAN script created by Haytham Taymour email: haytham.taymour@gmail.com")

#print directory
#print os.path.exists(directory)
#print fileexist

def clear_buffer(connection):
    buff = ""
    while connection.recv_ready():
        buff = buff + connection.recv(99)
    return(buff)
        
         
          
def get_logons():
    file_path = r"./<filename_of_user_and_pass_and_jumpserver_IP_each_in_a_new_line>"
    directory = os.path.dirname(file_path)
    fileexist = os.path.isfile(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

    if not(fileexist) or (len(sys.argv) > 2 and str(sys.argv[2]) == 'login') :

        try :
            f = open (file_path,"wb")
            username = input("enter your jump server username :")
            password = getpass("enter your jump server password :")
            server = input("enter jump server IP :")
            f.write(username + '\r\n')
            f.write(password + '\r\n')
            f.write(server + '\r\n')
            f.close()

        except:
            print ("Error creating file." + os.path.dirname(file_path))


    f = open (file_path,"r")
    data =  f.readlines()
    username = data[0][:-1]
    password = data[1][:-1]
    server = "10.57.59.165"
    if len(sys.argv) < 2 :
        print ("Fortiname name not found.")
        print ("""usage  :    edge_rouver <forti_name/ip>  login   ---> to renter your logins and server IP
                edge_rover <forti_name/ip>  ---> to rover a Forti device generating report document""")
        exit()

    router_name = str(sys.argv[1])
    f.close()
    print (username)
    #print password
    print (router_name)
    print (server)
    return(router_name,server,username,password)
    #################################################






class Router:
    def __init__(self, name, route='', policy=None, admin=None, interfaces=None):
        self.name = name
        self.route = route if route else {}
        self.policy = policy if policy is not None else {}
        self.admin = admin if admin is not None else {}
        self.interfaces = interfaces if interfaces is not None else []
        self.ssh = None
        self.channel = None    
    def connect(self, server, username, password):
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(server, username=username, password=password, allow_agent=False, banner_timeout=60)
            self.channel = self.ssh.invoke_shell()
            time.sleep(2)
            out = self.channel.recv(9999)
            print(out.decode('ascii'))
            # print("Connection established successfully.")
            return(out)
        except Exception as e:
            print("Connection not established correctly. Please make sure the IP is correct and authenticate the server before running.")
            print("Error:", e)
            if self.ssh: self.ssh.close()
    def ssh_cmd(self, cmd):
        if self.channel:
            # stdin, stdout, stderr = self.ssh.exec_command(command)
            # output = stdout.readlines()
            # print (self.channel)
            result = []
            self.channel.send(cmd)
            time.sleep(len(cmd)/50 + 0.5)
            out = self.channel.recv(9999).decode('ascii').split('\n')[0:-3]
            # print (out)
            for f,x in enumerate(out) : 
                if self.name.upper() + " (global) $" in x: continue
                if "Command fail" in x: continue
                if "error " in x: continue
                if "end " in x: continue
                if "Unknown action" in x: continue
                else : 
                    result.append(x)
            return ("\n".join(result))
        else:
            print("Connection not established. Please connect first.")
            return None        
    def close_connection(self):
        if self.ssh:
            self.ssh.close()
            print("Connection closed.")




router_name,server,username,password = get_logons()
print ("Connecting to server. Please be patient ...")
fg = Router(name = router_name)
out = fg.connect(server, username, password)



if str(out)[-3] != "$":
    print ("Connection not established correctly. Please make sure jump server IP is correct and authenticate iad server before running.")
    print ("use edge_rouver <router_name>  to rover your forti edge device. Note your logins and server IP")
    exit ()
elif str(out)[-3] == "$":
    print ("Connected sucessfully on the ONIS IP " + server)
    
    # subprocess.call(["python", "ips.py"])
    print ("**************** Telneting Fortinet Edge " + fg.name + " ************")
    out = fg.ssh_cmd("ssh "+ fg.name +" \n")
    time.sleep(1)
    if 'yes/no' in out: fg.ssh_cmd("yes\n")
    time.sleep(2)
    out = fg.ssh_cmd(password+"\n")
    time.sleep(0.5)
    fg.ssh_cmd("a\n\n\n           \n")
    fg.ssh_cmd("config global     \n\n")
    print ("\n\n\n################################ START ROVER REPORTING ON EDGE " +  fg.name + " ##########################")
    print(fg.ssh_cmd("get system ha status \n"))
    print(fg.ssh_cmd("get system status \n"))
    print(fg.ssh_cmd(r'get system status | grep "build8887\|HA mode\|cer" ' + '\n'))


    print ("\n\n\n################################ GLOBAL OPTIONS  ###########################################")
    # print(fg.ssh_cmd('	show system interface wan2	\n'))
    print(fg.ssh_cmd('show system ntp	\n'))
    print(fg.ssh_cmd('show system dns	\n'))
    print(fg.ssh_cmd('show system snmp user	\n'))
    print(fg.ssh_cmd('show system snmp sysinfo	\n'))
    print(fg.ssh_cmd('show system snmp mib-view	\n'))
    print(fg.ssh_cmd('show system global | grep timer	\n'))
    print(fg.ssh_cmd('show log syslogd setting	\n'))
    print(fg.ssh_cmd('show log syslogd filter	\n'))
    print(fg.ssh_cmd('show log fortianalyzer setting	\n'))
    print(fg.ssh_cmd('show switch-controller managed-switch	      \n\n\n'))

    
    print ("\n\n\n################################ HARDWARE NETWORK INTETFACE ###########################################")
    ports_list = fg.ssh_cmd('get hardware nic	\n')
    print(ports_list)
    # print(fg.ssh_cmd('get hardware nic internal1 | grep "Admin\|Speed\|Duplex\|link_status"\n'))
    # print(fg.ssh_cmd('get hardware nic internal2 | grep "Admin\|Speed\|Duplex\|link_status"\n'))
    # print(fg.ssh_cmd('get hardware nic internal3 | grep "Admin\|Speed\|Duplex\|link_status"\n'))
    # print(fg.ssh_cmd('get hardware nic internal4 | grep "Admin\|Speed\|Duplex\|link_status"\n'))
    # print(fg.ssh_cmd('get hardware nic wan1 | grep "Admin\|Speed\|Duplex\|link_status"\n'))
    # print(fg.ssh_cmd('get hardware nic b | grep "Admin\|Speed\|Duplex\|link_status"\n'))
    # print(fg.ssh_cmd('get hardware nic wan2 | grep "Admin\|Speed\|Duplex\|link_status"\n'))
    for port in ports_list.split()[8:-3]: print(fg.ssh_cmd('get hardware nic ' + port + ' | grep "Description\|Admin\|Speed\|Duplex\|link_status"\n '))


    print ("\n\n\n################################ INTETFACE DISCOVERY ###########################################")     
    interface_brief = fg.ssh_cmd("show system interface ? ")
    fg.ssh_cmd("\n\n")
    print (interface_brief.replace('0.0.0.0',''))
    print ("\n\n\n################################ DETAILED INTETFACE DISCOVERY #################################\n")  
    interface = fg.ssh_cmd("\nshow system interface \n   \n\n")
    i_list = interface.split('edit')[1:]
    print ("     # Name             VDOM       STATUS      TYPE             DESC             IP ")
    for g in i_list:  
        for l in g.split():
            if l in ['end',fg.name,'set', 'snmp-index', 'interface','next','allowaccess','description','vdom','type','"VM','alias','"ORCH=NETWORK"','ip','role','lldp-reception','enable','mtu-override','status'] :pass
            else: print (l.strip('"')+'   ', end='')
        print('\n',end ='')

    
    print ("\n\n\n################################ SYSTEM PERFORMANCE ###########################################")   
    print (fg.ssh_cmd('get system performance status\n'))
    



    # ====
    # ROOT
    # ====
    # show sytem interface loopback1111
    # show router static
    # get router info routing-table all
    # get router info routing-table details 57.67.56.100/32
    # show firewall addrgrp "g-MSZ"
    # show firewall address "MSZ1"  
    # get vpn ipsec tunnel summary
    # diagnose sys link-monitor status 
    fg.ssh_cmd('end\n')
    fg.ssh_cmd('config vdom\n\n')
    fg.ssh_cmd('edit root\n\n')
    print ("\n\n\n###########################################################################")
    print ("##########                         ROOT VDOM              ##########")
    print ("###########################################################################")
    print ("\n\n\n###################### Managment IP sec tunnels############################")
    print(fg.ssh_cmd('get vpn ipsec tunnel summary\n'))
    print(fg.ssh_cmd('diagnose vpn tunnel list\n'))
    print(fg.ssh_cmd('show vpn ipsec phase1-interface sgwn_inet1 \n'))
    print(fg.ssh_cmd('show vpn ipsec phase1-interface sgwn_inet2 \n'))
    print ("################################ STATIC ROUTING INFO ############################")
    print(fg.ssh_cmd('get router info routing-table static \n'))
    print ("\n\n\n############################# ALL  ROUTING TABLE #######################################")
    print (fg.ssh_cmd('get router info routing-table all\n\n\n\n'))
    print (fg.ssh_cmd('get router info routing-table details 57.66.27.70\n\n\n'))
    print ("################################ LINK Monitoring status ############################")
    print(fg.ssh_cmd('show system link-monitor \n'))
    print(fg.ssh_cmd('diagnose sys link-monitor status \n\n\n'))
    print ("\n\n\n############################# FW POLICY #######################################")
    print(fg.ssh_cmd('show firewall policy \n   \n'))
    print ("\n\n\n############################# FW Group and Objects #######################################")
    print(fg.ssh_cmd('show firewall addrgrp \n\n\n'))
    print(fg.ssh_cmd('show firewall address \n\n\n'))



    #     =========
    # VDOM-CUST
    # =========
    # get router info routing-table all
    # show router policy          # PBR 
    # show system dns-database
    # show log setting
    # show log syslogd override-setting
    # show log syslogd2 override-setting
    # show log syslogd override-filter
    # show log memory filter
    # show log null-device setting

    # show system vdom-dns
    # show system vdom-netflow

    # get system interface
    # show router static | grep wan2.vlan -f
    # show vpn ipsec phase1-interface | grep auto-discovery-receiver
    # get vpn ipsec tunnel summary
    # get router info bgp summary 
    # get router info bgp neighbors 160.222.206.126 advertised-routes
    # get router info bgp neighbors 160.222.206.254 advertised-routes
    # get router info bgp neighbors 160.222.207.126 advertised-routes
    # get router info bgp neighbors 160.222.207.254 advertised-routes
    # diagnose sys sdwan health-check

    # execute ping-options data-size 1600
    # execute ping-options source 47.58.17.71

    fg.ssh_cmd('end\n')
    fg.ssh_cmd('config vdom\n\n')
    fg.ssh_cmd('edit VDOM-CUST\n\n')

    print ("\n\n\n###########################################################################")
    print ("##########                         CUST VDOM              ##########")
    print ("###########################################################################")
    print ("\n\n\n###################### SERVICE IP sec tunnels############################")
    print(fg.ssh_cmd('get vpn ipsec tunnel summary\n'))
    print(fg.ssh_cmd('diagnose vpn tunnel list\n'))
    print(fg.ssh_cmd('show vpn ipsec phase1-interface sgwn_inet1 \n'))
    print(fg.ssh_cmd('show vpn ipsec phase1-interface sgwn_inet2 \n'))

    print ("################################ STATIC ROUTING INFO ############################")
    print(fg.ssh_cmd('get router info routing-table static \n'))
    print ("\n\n\n############################# BGP ROUTING  #######################################")
    print (fg.ssh_cmd('get router info bgp summary \n'))
    print (fg.ssh_cmd('get router info bgp neighbors 192.168.201.126 advertised-routes\n'))
    print (fg.ssh_cmd('get router info bgp neighbors 192.168.201.254 advertised-routes\n'))  
    print ("\n\n\n############################# ALL  ROUTING TABLE #######################################")
    # print (fg.ssh_cmd('get router info routing-table all\n  ))
    print (fg.ssh_cmd('get router info routing-table details 192.168.201.126\n\n'))

    
    print ("################################ LINK Monitoring status ############################")
    print(fg.ssh_cmd('show system link-monitor \n'))
    print(fg.ssh_cmd('diagnose sys link-monitor status \n\n\n'))
    print ("\n\n\n############################# FW POLICY #######################################")
    r1 = fg.ssh_cmd('show firewall policy \n                        \n')
    r2 = fg.ssh_cmd('\n\n')
    r3 = fg.ssh_cmd('\n\n')
    policy = r1 + r2 + r3
    try : 
        p_list = policy.split('edit')[1:]
        print ("#Name                    / SRC INT  /  DEST INT /            SRC ADD / DEST ADD               / ACTION        / SERVICES ")
        for g in p_list:  
            for l in g.split():
                l = l.strip()
                if l == 'action' or l == 'service' or 'dst' in l or 'src' in l : print ('/ ', end='')
                if l.startswith('WebFilter') or 'WebFilter' in l or 'Arkas_ssl_ins_60F' in l or 'arkasAppContr' in l or 'AV' in l or 'Bimar' in l or 'webfilter' in l or 'start' in l or 'GROUPS' in l or 'groups' in l or 'Webfilter' in l or 'certificate-inspection' in l :  continue
                if l in ['end',fg.name,'Arkas_ssl_ins_60F','set','av-profile','FortiGuard','application-list','s-FortiSandboxCloud','utm-status','enable','disable','logtraffic','nat','ssl-ssh-profile','ips-sensor','application', 'uuid', 'srcintf','srcaddr','dstintf','dstaddr','next','schedule','action','schedule','service','"always"','$','name','(VDOM-CUST)','fsso-groups','all'] :continue
                if len(l) > 29 : continue
                print (l.strip('"')+'   ', end='')
            print('\n',end ='')

    except : pass
    print ("\n\n\n################################ SYSTEM PERFORMANCE ###########################################")   
    print (fg.ssh_cmd('get system performance status\n'))
    print ("\n\n\n############################# FW Group and Objects #######################################")
    print(fg.ssh_cmd('show firewall addrgrp | grep -v uuid\n    \n').replace("set",'').replace("next",'--------------------------------------------').replace("edit", 'Name'))
    print(fg.ssh_cmd('show firewall address | grep -v uuid\n    \n').replace("set",'').replace("next",'--------------------------------------------').replace("edit", 'Name'))
    print ("\n\n\n############################# POLICY Routing #######################################")
    print (fg.ssh_cmd(' show router policy \n\n\n'))
    print ("\n\n\n############################# SD WAN  #######################################")
    print (fg.ssh_cmd(' diagnose sys sdwan zone \n'))
    print (fg.ssh_cmd(' diagnose sys sdwan member \n'))
    print (fg.ssh_cmd(' diagnose sys sdwan health-check \n '))
    service = fg.ssh_cmd(' show system sdwan \n ')
    try : print ("RULES : \n config service" + service.split('config service')[1])
    except : pass
    print ("\n\n\n#############################   ARP  #######################################")
    print (fg.ssh_cmd('get system arp\n  \n'))

    print ("\n\n\n############################# SERVICES #######################################")


    print (fg.ssh_cmd('show system dns-database\n'))
    print (fg.ssh_cmd('show system vdom-dns\n'))
    print (fg.ssh_cmd('show log setting\n'))
    print (fg.ssh_cmd('show system dhcp server \n'))
    print (fg.ssh_cmd('show switch-controller managed-switch\n'))
    print (fg.ssh_cmd('get system session list | grep -c tcp\n'))
    print (fg.ssh_cmd('get system session list | grep -c udp\n'))



    # show system vdom-dns
    # show system vdom-netflow

    # get system interface
    # show router static | grep wan2.vlan -f
    # show vpn ipsec phase1-interface | grep auto-discovery-receiver
    # get vpn ipsec tunnel summary

    exit()

