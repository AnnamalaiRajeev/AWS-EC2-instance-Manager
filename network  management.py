#!/usr/bin/env python
import subprocess
import sys
import copy
from prettytable import PrettyTable
from scapy.all import rdpcap
from scapy import route
import sys
from StringIO import StringIO
import smtplib

fromaddr = 'rajeevchinni@gmail.com'
toaddrs = 'rajeevchinni@gmail.com'
username = 'rajeevchinni'
password = '************'
packets = rdpcap('dump_1.pcap')
for pkt in packets:
    if (pkt.haslayer('UDP')):
        if (pkt['UDP'].dport == 162):
            server = smtplib.SMTP("smtp.gmail.com:587")
            server.starttls()
            server.login(username, password)
            capture = StringIO()
            save_stdout = sys.stdout
            sys.stdout = capture
            pkt.show()
            sys.stdout = save_stdout
            value = capture.getvalue()
            server.sendmail(fromaddr, toaddrs, value)
            # str(pkt.show())
            # print(yo)
            server.quit()


def printer_data(dict_1, dict_2, dict_3, num_1, num_2, num_3):
    x = PrettyTable()
    list_keys = list(dict_1.keys())
    n_columns = len(list_keys)
    columns_list = ["column_1", "column_2", "column_3", "column_4", "column_5", "column_6"]
    i = 0
    for key in list_keys:
        columns_list[i] = copy.deepcopy(dict_1[key] + dict_2[key] + dict_3[key])
        i += 1
    x.add_column("Routers", ["R1"] * num_1 + ["R2"] * num_2 + ["R3"] * num_3)
    i = 0
    for column in columns_list:
        x.add_column(list_keys[i], columns_list[i])
        i += 1
    print(x)


##-----------v2------------------------------------##
##-----------R1------------------------------------##


ucast = check_outpup1 = subprocess.Popen(["snmpbulkwalk -v2c -Os -c public 198.51.100.3 ifinUc"],
                                         stdout=subprocess.PIPE, shell=True)
AdminStatus = check_outpup1 = subprocess.Popen(["snmpbulkwalk -v2c -Os -c public 198.51.100.3 ifAdminStatus"],
                                               stdout=subprocess.PIPE, shell=True)
PhysAddress = check_outpup1 = subprocess.Popen(["snmpbulkwalk -v2c -Os -c public 198.51.100.3 ifPhysAddress"],
                                               stdout=subprocess.PIPE, shell=True)
OperStatus = check_outpup1 = subprocess.Popen(["snmpbulkwalk -v2c -Os -c public 198.51.100.3 ifOperStatus"],
                                              stdout=subprocess.PIPE, shell=True)
ifDescr = check_outpup1 = subprocess.Popen(["snmpbulkwalk -v2c -Os -c public 198.51.100.3 ifDescr"],
                                           stdout=subprocess.PIPE, shell=True)
ifName = check_outpup1 = subprocess.Popen(["snmpbulkwalk -v2c -Os -c public 198.51.100.3 ifName"],
                                          stdout=subprocess.PIPE, shell=True)

list_er = ["ifAdminStatus", "ifPhysAddress", "ifOperStatus", "ifDescr", "ifName", "ifInUcas    t"]
ucast_v2, error = ucast.communicate()
AdminStatus_v2, error = AdminStatus.communicate()
PhysAddress_v2, error = PhysAddress.communicate()
OperStatus_v2, error = OperStatus.communicate()
ifDescr_v2, error = ifDescr.communicate()
ifName_v2, error = ifName.communicate()
# print("{} \n {} \n {} \n {} \n {} \n {} \n".format(ucast_v2,AdminStatus_v2,PhysAddress_v2,OperStatus_v2,ifDescr_v2,ifName_v2))
dict_1 = {"ifAdminStatus": AdminStatus_v2, "ifPhysAddress": PhysAddress_v2, "ifOperStatus": OperStatus_v2,
          "ifDescr": ifDescr_v2, "ifName": ifName_v2, "ifInUcast": ucast_v2}
print("----------------R1---------------")
for key in dict_1:
    print(dict_1[key])

##--------#V3##------------------------------------------------------
##---------#R3##---------------------------------------------
list_er = ["ifAdminStatus", "ifPhysAddress", "ifOperStatus", "ifDescr", "ifName", "ifInUcast"]
list_o = ["p1", "p2", "p3", "p4", "p5", "p6"]
dict_3 = {}
i = 0
for element in list_er:
    list_o[i] = subprocess.Popen(
        ["snmpbulkwalk", "-v", "3", "-l", "authpriv", "-u", "kelly", "-a", "SHA", "-A", "password", "-x", "DES", "-X",
         "password", "198.51.100.5", element], stdout=subprocess.PIPE)
    list_o[i].wait()
    output, error = list_o[i].communicate()
    # print(output)
    dict_3.update({element: output})
    i += 1
print("----------------R3---------------")

for key in dict_3:
    print(dict_3[key])
###------------------------v2--------------------------------##
###-------------------------R2-------------------------------##

list_er = ["ifAdminStatus", "ifPhysAddress", "ifOperStatus", "ifDescr", "ifName", "ifInUcast"]
list_o = ["p1", "p2", "p3", "p4", "p5", "p6"]
dict_2 = {}
i = 0
for element in list_er:
    list_o[i] = subprocess.Popen(["snmpbulkwalk", "-v", "2c", "-c", "public", "198.51.100.4", element],
                                 stdout=subprocess.PIPE)
    list_o[i].wait()
    output, error = list_o[i].communicate()
    print(output)

    dict_2.update({element: output})
    i += 1
###-------------------------R2-------------------------------##
###------------------------v2--------------------------------##
print("---------------R2----------------")
for key in dict_2:
    print(dict_2[key])
###----Number of interfaces-------------####

number_1s = subprocess.Popen(["snmpget -v 1 -c public 198.51.100.3 ifNumber.0"], stdout=subprocess.PIPE, shell=True)
number_2s = subprocess.Popen(["snmpget -v 1 -c public 198.51.100.4 ifNumber.0"], stdout=subprocess.PIPE, shell=True)
number_3s = subprocess.Popen(
    ["snmpget -v3 -l authpriv -u kelly -a SHA -A password -x DES -X password 198.51.100.5 ifNumber.0"],
    stdout=subprocess.PIPE, shell=True)

num_1, error_1 = number_1s.communicate()
print(num_1)
num_list = num_1.split()
num_1 = int(num_list[-1])
num_2, error_2 = number_2s.communicate()
num_list = num_2.split()
num_2 = int(num_list[-1])
num_3, error_3 = number_3s.communicate()
num_list = num_3.split()
num_3 = int(num_list[-1])
number = num_1 + num_2 + num_3
print(number)
variable_dict = copy.deepcopy(dict_1)

for key in variable_dict:
    string_list = variable_dict[key].splitlines()
    string_list.pop(-1)
    final_list = [element.split()[-1] for element in string_list]
    dict_1.update({key: final_list})

variable_dict = copy.deepcopy(dict_2)
for key in variable_dict:
    string_list = variable_dict[key].splitlines()
    string_list.pop(-1)
    final_list = [element.split()[-1] for element in string_list]
    dict_2.update({key: final_list})

variable_dict = copy.deepcopy(dict_3)
for key in variable_dict:
    string_list = variable_dict[key].splitlines()
    string_list.pop(-1)
    final_list = [element.split()[-1] for element in string_list]
    dict_3.update({key: final_list})

print("{}\n{}\n{}\n{}".format(dict_1, dict_2, dict_3, number))

##---------------------------------------------IP_addr & Subnetmask added--------##
ip_addr_string_R1 = subprocess.Popen(["snmpwalk -v 1 -c public 198.51.100.3 ipAdEntnet"], stdout=subprocess.PIPE,
                                     shell=True)
ip_addr_string_R2 = subprocess.Popen(["snmpwalk -v 2c -c public 198.51.100.4 ipAdEntnet"], stdout=subprocess.PIPE,
                                     shell=True)
ip_addr_string_R3 = subprocess.Popen(
    ["snmpwalk -v3 -l authpriv -u kelly -a SHA -A password -x DES -X password 198.51.100.5 ipAdEntnet"],
    stdout=subprocess.PIPE, shell=True)
output_R1_string, error = ip_addr_string_R1.communicate()
output_R2_string, error = ip_addr_string_R2.communicate()
output_R3_string, error = ip_addr_string_R3.communicate()
dict_ed = {1: output_R1_string, 2: output_R2_string, 3: output_R3_string}
for i in range(1, 4):
    print("the Active interfaces and their subnets on the Router R{} are:".format(i))
    for line in dict_ed[i].splitlines():
        print("ip Address:{} subnetmask is: {}".format(line.split("k.")[1].split(" ")[0],
                                                       line.split("k.")[1].split(" ")[3]))

printer_data(dict_1, dict_2, dict_3, num_1 - 1, num_2 - 1, num_3 - 1)
