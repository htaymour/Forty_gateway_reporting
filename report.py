import paramiko
from prettytable import PrettyTable
import time
import re
import os
import sys

server = '192.168.80.46'
username = ''
password = ''

print ("Connecting to server. Please wait ...")
try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server, username=username,password = password, allow_agent=True)
    stdin,stdout,stderr = ssh.exec_command("\n")
    output = stdout.readlines()
    print ("\n".join(output))
except Exception as e:
    print ("Connection not established correctly. Please make sure IP is correct.")
    print ("error :",e)
    ssh.close
    sys.exit()

channel = ssh.invoke_shell()
channel.send("\n\n\n")
channel.send("cphaprob stat\n")
time.sleep(2)
out1 = channel.recv(9999)
# print (out1)
channel.send("vsx stat -v\n")
time.sleep(2)
out2 = channel.recv(9999)
# print (out2)
ssh.close()

out1 = out1.decode()
out2 = out2.decode()
o = out1.split("-------+-------+-----------+-----------+-----------+-----------")
table1 = o[1].split("---------------+-----------+-----------+-----------+-----------")[0]

gw = o[0].split("|")
gw1 = gw[2].strip(' ')+gw[7].strip(' ')
gw2 = gw[3].strip(' ')+gw[8].strip(' ')
gw3 = gw[4].strip(' ')+gw[9].strip(' ')
gw4 = gw[5].strip(' ').strip('\n').strip('\r')+gw[10].strip(' ').strip('\n').strip('\r').strip(' ')

table2 = out2.split("======================")[1].split('Type:')[0].split('-----+-------------------------+-----------------------+-----------------+--------------------------+---------')[1]
table2list = []
for x in range(1,len(table2.split('\n'))-3):
    id = table2.split('\n')[x].split('|')[0].strip(' ')
    name = table2.split('\n')[x].split('|')[1].strip(' ').strip('S ')
    policy = table2.split('\n')[x].split('|')[2].strip(' ').strip('.')
    table2list.append(id)
    table2list.append(name)
    table2list.append(policy)


################################ GET MEMORY AND CONNECTION STATUS ON EACH NODE ##############
gwlist = []
gwlist.append(gw1), gwlist.append(gw2), gwlist.append(gw3), gwlist.append(gw4)
dev_dict = {}
# dev_dict = dict.fromkeys(gwlist,{'memory':'','conn':'','peak':''})
gw1_parm = []
gw2_parm = []
gw3_parm = []
gw4_parm = []

ssh.close()
for device in gwlist:
    print ("Connecting to device " + str(device))
    try:
        ssh.connect(device, username=username,password = password, allow_agent=True)
        stdin,stdout,stderr = ssh.exec_command("\n")
        output = stdout.readlines()
        print ("\n".join(output))
        channel = ssh.invoke_shell()
        channel.send("\n\n\n")
        channel.send("fw vsx mstat\n")
        time.sleep(4)
        out1 = channel.recv(9999)
        # print (out1) 
        cmd = "vsx stat -l | grep -E 'VSID|Conn' \n"
        channel.send(cmd)
        time.sleep(3)
        out2 = channel.recv(9999)
        # print (out2)
        ssh.close()
    except Exception as e:
        print ("Connection not established correctly on device" + device)
        print ("error :",e)
        ssh.close
        sys.exit()
        print("connection not sucessfull")
    #### MEMORY ADD TO DICTIOARIES 
    out1 = out1.decode()
    out2 = out2.decode()
    o = out1.split("======+====================")[1].strip("\r\n").split("\n")
    d_dict = {}
    o.remove('\r')
    o.pop(-1)
    for x in o:
        x = x.strip('\r')
        ID = x.split('|')[0].strip(' ')
        MEMORY = x.split('|')[1].strip(' ')
        # print(ID)  # ID
        # print(MEMORY)  # Memory
        d_dict [ID] = MEMORY

    if device == gw1 : gw1_parm.append(d_dict)

    if device == gw2 : gw2_parm.append(d_dict)

    if device == gw3 : gw3_parm.append(d_dict)

    if device == gw4 : gw4_parm.append(d_dict)

    dev_dict[device] = {'memory': d_dict}
    print (device)
    # print (d_dict)
    #### CONN AND PEAK ADD TO DICTIOARIES
    conn_dict = {}
    peak_dict = {}
    o = out2.split("\r\n")
    o.pop(-1)
    o.pop(0)
    for x in range(0,len(o)-2,4) : 
        ID = o[x].strip('VSID:').strip(' ')
        C_NUM = o[x+1].strip('Connections number: ')
        C_PEAK = o[x+2].strip('Connections peak:').strip(' ')
        # print (str(ID) , str(C_NUM) ,str(C_PEAK) )
        conn_dict [ID] = C_NUM
        peak_dict [ID] = C_PEAK
    # print (conn_dict)
    dev_dict[device] = {'conn': conn_dict}
    dev_dict[device] = {'peak': peak_dict}
    if device == gw1 :
        gw1_parm.append(conn_dict)
        gw1_parm.append(peak_dict)

    if device == gw2 : 
        gw2_parm.append(conn_dict)
        gw2_parm.append(peak_dict)

    if device == gw3 : 
        gw3_parm.append(conn_dict)
        gw3_parm.append(peak_dict)

    if device == gw4 : 
        gw4_parm.append(conn_dict)
        gw4_parm.append(peak_dict)




############################# BUILDING FINAL TABLE TO PRINT ON SCREEN #########################

t = PrettyTable(["ID" ," VS Name "," Policy Name "," Active GW ","Memory usage","Connections","Peak connection"])
t.align["VSID"] = "l"
t.align["Name"] = "l"
t.align["Security Policy"] = "l"
t.align["Active Gateway"] = "l"
HTML_FILE = """<!DOCTYPE html>
<html>
<head>
<style>
table {
  font-family: arial, sans-serif;
  border-collapse: collapse;
  width: 100%;
}

td, th {
  border: 1px solid #dddddd;
  text-align: left;
  padding: 8px;
}

tr:nth-child(even) {
  background-color: #dddddd;
}
</style>
</head>
<body>

<h2>Cluster Check Point 6800 PD</h2>

<table>
  <tr>
    <th>VSID</th>
    <th>NAME</th>
    <th>Security Policy</th>
    <th>Active Gateway</th>
    <th>Memory usage</th>
    <th>Connections</th>
    <th>Peak connection</th>
  </tr>
"""

for x in range(1,len(table1.split('\n'))-2):
    table3  = []
    id = table1.split('\n')[x].split('|')[0].strip('\r').strip(' ')
    g1 = table1.split('\n')[x].split('|')[2].strip('\r').strip(' ')
    g2 = table1.split('\n')[x].split('|')[3].strip('\r').strip(' ')
    g3 = table1.split('\n')[x].split('|')[4].strip('\r').strip(' ')
    g4 = table1.split('\n')[x].split('|')[5].strip('\r').strip(' ')
    table3.append (id)
    table3.append (table2list[(int(id)-1)*3 + 1])   # NAME
    table3.append (table2list[(int(id)-1)*3 + 2])   # POLICY
    if g1 == 'ACTIVE' : table3.append (gw1) , table3.append(gw1_parm[0][str(id)]) , table3.append(gw1_parm[1][str(id)]) , table3.append(gw1_parm[2][str(id)])
    if g2 == 'ACTIVE' : table3.append (gw2) , table3.append(gw2_parm[0][str(id)]) , table3.append(gw2_parm[1][str(id)]) , table3.append(gw2_parm[2][str(id)])
    if g3 == 'ACTIVE' : table3.append (gw3) , table3.append(gw3_parm[0][str(id)]) , table3.append(gw3_parm[1][str(id)]) , table3.append(gw3_parm[2][str(id)])
    if g4 == 'ACTIVE' : table3.append (gw4) , table3.append(gw4_parm[0][str(id)]) , table3.append(gw4_parm[1][str(id)]) , table3.append(gw4_parm[2][str(id)])
    # table3.append(dev_dict[table3[3]]['memory'][str(id)])
    # table3.append(dev_dict[table3[3]]['conn'][str(id)])
    # table3.append(dev_dict[table3[3]]['peak'][str(id)])
    t.add_row([table3[0],table3[1],table3[2],table3[3],table3[4],table3[5],table3[6]])
    HTML_FILE = HTML_FILE + """    <tr>
    <td>%s</td>
    <td>%s</td>
    <td>%s</td>
    <td>%s</td>
    <td>%s</td>
    <td>%s</td>
    <td>%s</td>
  </tr>
""" %(table3[0],table3[1],table3[2],table3[3],table3[4],table3[5],table3[6])

print(t.get_string(title="Cluster Check Point 6800 PD"))
HTML_FILE = HTML_FILE + """</table>

</body>
</html>
"""


f = open("/usr/web_rete/site/Firewall/TABLE.HTML", "w")
f.write(HTML_FILE)
f.close()
print ("LINK to HTML :    http://10.5.4.32/Firewall/TABLE.HTML" )

