import cuckoo.utils.submit as submit
import objects_ASX
from mongodb_ASX import my_mdb
import datetime
import time
import thread
from collections import deque
from util.color import *
from cuckoo import cuckoo
import json
from subprocess import call as cmd_line, check_output
from os import path
import re
import urllib2
from HTMLParser import HTMLParser
from multiprocessing import Pool
import netaddr
import hashlib
import traceback
#layer_2A - get the apk info and decomplie the app
#layer_2B - get network conversations and ip void info
#
layer_2_global_var  = objects_ASX.global_var()


def layer_2_A():
# This section need to be multithreaded it takes long time and could be done parallely
    local_mdb = my_mdb()
    temp_queue = deque()
    results = local_mdb.cl_analysis_tickets.find({"current_analysis_layer":"layer_2A", "analysis_status":{"$in":["incomplete","new"]}})  #"analysis_status":{"$in":["failed"]}}) #
    if results.count() == 0:
        print(yellow("No layer_2A tickets pending"))
        return
    for each in results:
        ticket = objects_ASX.ticket(each)
        temp_queue.append(ticket)


    pool_of_threads = Pool(4)
    while len(temp_queue) !=0:
        temp_ticket = temp_queue.popleft()
        pool_of_threads.apply_async(get_apk_info_thread_fn,(temp_ticket,))
    pool_of_threads.close()
    pool_of_threads.join()

    local_mdb.close()
    # from here
    '''
    while len(temp_queue) !=0:
        temp_ticket = temp_queue.popleft()
        while True:
            print "I am trying to fetch cuckcoo ticket for:: ",temp_ticket.file_path
            temp_cuckoo_ticket = temp_mdb.cl_analysis.find_one({"target.file.sha256":temp_ticket.hash_sha256})
            if temp_cuckoo_ticket == None:
                print "Result yet not fetched so Sleeping for 6 sec"
                time.sleep(6)
            else:
                break

        if temp_cuckoo_ticket is not None:
            #print temp_cuckoo_ticket
            temp_ticket.cuckoo_id = temp_cuckoo_ticket['_id']
            temp_ticket.cuckoo_folder_id = temp_cuckoo_ticket['info']['id']
            temp_ticket.apktool_data_path = get_apktool_info(temp_ticket)
            temp_ticket.android_app_name = get_app_name(temp_ticket.apktool_data_path)
            if(temp_mdb.cl_analysis_tickets.find_one({'hash_sha256':temp_ticket.hash_sha256})) == None:
                temp_mdb.cl_analysis_tickets.insert(temp_ticket.give_dict())

            print "Ticket id ::", temp_ticket.ticket_id
            print "Analysis Ticket: %s\n"%(temp_ticket)
        else:
            print "temp_cuckoo_ticket is none"
    '''
    #till here




def get_apk_info_thread_fn(temp_ticket):
    temp_1 = 0
    temp_mdb = my_mdb()
    try:
        while True:
            print "I am trying to fetch cuckcoo ticket for:: ",temp_ticket.file_path
            temp_cuckoo_ticket = temp_mdb.cl_analysis.find_one({"target.file.sha256":temp_ticket.hash_sha256})
            if temp_cuckoo_ticket == None:
                #print "Result yet not fetched so Sleeping for 12 sec"

                print(red("failed analysis for ticket_id:%s hash:%s" % (temp_ticket.ticket_id, temp_ticket.hash_sha256)))
                temp_ticket.analysis_status = "failed"
                temp_mdb.cl_analysis_tickets.update({"ticket_id": temp_ticket.ticket_id},{'$set': temp_ticket.give_dict()})
                return

                '''
                time.sleep(20)
                if temp_1 == 15:
                    print(red("failed analysis for ticket_id:%s hash:%s"%(temp_ticket.ticket_id,temp_ticket.hash_sha256)))
                    temp_ticket.analysis_status = "failed"
                    temp_mdb.cl_analysis_tickets.update({"ticket_id":temp_ticket.ticket_id},{'$set':temp_ticket.give_dict()})
                    return
                temp_1+=1
                '''
            else:
                break

        if temp_cuckoo_ticket is not None:
            #print temp_cuckoo_ticket
            temp_ticket.cuckoo_id = temp_cuckoo_ticket['_id']
            temp_ticket.cuckoo_folder_id = temp_cuckoo_ticket['info']['id']
            # commenting this as apktool is taking unexpectedly large time and its not required at this phase
            print(red("Not Running APKTOOL as it is taking too much of time"))
            #--- From here #1
            # temp_ticket.apktool_data_path = get_apktool_info(temp_ticket)
            temp_ticket.apktool_data_path = None
            # temp_ticket.android_app_name = get_app_name(temp_ticket.apktool_data_path)
            temp_ticket.android_app_name = None
            #--- till here #1

            temp_ticket.current_analysis_layer = "layer_2B"
            temp_ticket.analysis_status = "incomplete"
            # if(temp_mdb.cl_analysis_tickets.find_one({'hash_sha256':temp_ticket.hash_sha256})) == None:
            #     temp_mdb.cl_analysis_tickets.insert(temp_ticket.give_dict())

            print "Ticket id ::", temp_ticket.ticket_id
            print "Analysis Ticket: %s\n"%(temp_ticket)
            temp_mdb.cl_analysis_tickets.update({"ticket_id":temp_ticket.ticket_id},{'$set':temp_ticket.give_dict()})
        else:
            print "temp_cuckoo_ticket is none"
    except KeyboardInterrupt:
        print("KeyboardInterrupt in thread")
        return
    except:
        traceback.print_exc()

    temp_mdb.close()

def get_apktool_info(temp_ticket):  # Finction not in use
    print yellow("Attempting to perform apktool based decomilation >> Tocket_ID : %s"%(temp_ticket.ticket_id))
    androSandx_path = path.split(path.abspath(__file__))[0]
    apktool_path = path.join(androSandx_path,"apktool","apktool")
    extract_dir_name = path.join(androSandx_path,"cuckoo","storage","analyses",str(temp_ticket.cuckoo_folder_id),"apktool")
    #extract_dir_name = path.join(androSandx_path,"cuckoo","storage","analyses","12","apktool")

    #print "extract_dir_name",extract_dir_name
    #print("command :"+apktool_path+" "+"d"+" "+temp_ticket.file_path+" "+"--output"+" "+extract_dir_name+"-f")
    cmd_line([apktool_path,"d","-d",temp_ticket.file_path,"--output",str(extract_dir_name),"-f"])

    # rebuild apk in debug mode
    #commenting this as this takes very long time and decompiled version have very large size

    """
    enable for only manual decompilation and recompilation and debugging
    """
    #cmd_line([apktool_path,"b","-d",str(extract_dir_name)])

    #print "temp_ticket.file_path :",temp_ticket.file_path
    # Decode apk in debug mode: $ apktool d -d -o out app.apk
    # Build new apk in debug mode: $ apktool b -d out

    return extract_dir_name

def get_app_name(extract_dir_name):   #Function not in use
    print yellow("Attempting to extract actual app name >> ")
    try:
        manifest_file = open(path.join(extract_dir_name,'AndroidManifest.xml'),"r")
        temp_string_1 = manifest_file.read()
        reg1 = re.compile(r"<application(.*)?android:label=(\"(.*)?\"|\'(.*)?\')")
        temp_string = reg1.search(temp_string_1).group(0)
        del temp_string_1
        if temp_string == None:
            print "No apk name found"
        else:
            temp_string = re.search(r"android:label=.*?\".*?\"",temp_string).group(0)
            temp_string = temp_string.replace("android:label=","")
            temp_string = temp_string.replace("\"","")
            (file_1,string_2) = temp_string.split("/")
            file_1 = file_1.replace("@","")
            if file_1 != "public":
                file_1 = file_1.replace("@","") + "s.xml"
            else:
                file_1 = file_1.replace("@","") + ".xml"
            #print path.join(extract_dir_name,"res","values",file_1)
            file_contining_name = open(path.join(extract_dir_name,"res","values",file_1),"r")
            temp_string = file_contining_name.read()
            search_string  = ""
            app_name = re.search(r"\"%s\">.*?<"%(string_2),temp_string).group(0)
            app_name = app_name.split(">")[1]
            app_name = app_name.replace("<","")
            #<string name="app_name">Gentle Wakeup</string>

            #print "Temp String: ",temp_string
            print "file_1: ",file_1
            print "string_2: ",string_2
            print "app_name: ",app_name
        return app_name
    except:
        return "UNKNOW_FILED_TO_GET_NAME"

    #get name - regex "<application(.*)?android:label=("(.*)?"|'(.*)?')"

def layer_2_B():
    temp_mdb = my_mdb()
    results = temp_mdb.cl_analysis_tickets.find({"current_analysis_layer":"layer_2B"}) #,"analysis_status":{"$in":["incomplete","new"]}})
    # print("in 2B")
    if results.count() == 0:
        print(yellow("No layer 2B analysis pending"))
        return
    try:
        for each in results:
            try:
                ticket = objects_ASX.ticket(each)
                print("Working on ID: %s"%(ticket.ticket_id))
                if ticket.cuckoo_folder_id == None:
                    print(red("Cuckoo folder ID None for %s"%(ticket.ticket_id)))
                    continue
                io_phs, conv_tcp , conv_udp = get_network_conversations(ticket.cuckoo_folder_id)
                temp_mdb.cl_analysis.update({"target.file.sha256":ticket.hash_sha256},{'$set':{"input_output_protocol_hirarchy":io_phs,"tcp_conversation":conv_tcp,"udp_conversation":conv_udp}})
                temp_mdb.cl_analysis_tickets.update({"ticket_id":ticket.ticket_id},{'$set':{"current_analysis_layer":"layer_2C","analysis_status":"incomplete"}})
            except:
                continue
    except:
        exit()
    temp_mdb.close()
def get_flow_record():
    pass

def get_network_conversations(temp_ticket_cuckoo_folder_id):
    ASX_root_path = path.split(path.abspath(__file__))[0]
    dump_pcap_path = path.join(ASX_root_path,"cuckoo","storage","analyses",str(temp_ticket_cuckoo_folder_id),"dump.pcap")
    asx_ai_pcap_path = path.join(ASX_root_path,"cuckoo","storage","analyses",str(temp_ticket_cuckoo_folder_id),"asx_ai.pcap")

    # creating a pcap excluding google IPs
    cmd_line(["tshark","-r",dump_pcap_path,"-w",asx_ai_pcap_path,"-Y", "!(ip.addr == 64.18.0.0/20) and !(ip.addr == 64.233.160.0/19) and !(ip.addr == 66.102.0.0/20) and !(ip.addr == 66.249.80.0/20) and !(ip.addr == 72.14.192.0/18) and !(ip.addr == 74.125.0.0/16) and !(ip.addr == 108.177.8.0/21) and !(ip.addr == 173.194.0.0/16) and !(ip.addr == 207.126.144.0/20) and !(ip.addr == 209.85.128.0/17) and !(ip.addr == 216.58.192.0/19) and !(ip.addr == 216.239.32.0/19)" ])
    #capinfos -M
    # tshark -r dump.pcap -q -z http,tree
    # tshark -r dump.pcap -q -z conv.tcp,udp,ip
    # tshark -r dump.pcap -q -z io,phs

    # #print("HTTP_tree")
    # #cmd_line(["tshark","-r",asx_ai_pcap_path,"-n","-q","-z","http,tree"])
    # print("HTTP_req_tree")
    # cmd_line(["tshark","-r",asx_ai_pcap_path,"-n","-q","-z","http_req,tree"])
    # # domain and request
    #
    #
    # print("HTTP_srv_tree")
    # cmd_line(["tshark","-r",asx_ai_pcap_path,"-n","-q","-z","http_srv,tree"])
    #
    # '''


    # Protocol hirarchi
    # [proto_name, frames, bytes]
    io_phs = check_output(["tshark","-r",asx_ai_pcap_path,"-n","-q","-z","io,phs"])
    io_phs = re.sub(r"\s+"," ",io_phs)
    io_phs = re.sub(r"=================================================================== Protocol Hierarchy Statistics Filter: ","",io_phs)
    io_phs = re.sub(r"===================================================================","",io_phs)
    io_phs = re.findall(r"\s.*?frames:.*?bytes:\d+",io_phs)
    for x in range(0,len(io_phs)):
        io_phs[x] = io_phs[x].split(" ")
        del io_phs[x][0]
        io_phs[x][1] = io_phs[x][1].replace("frames:","")
        io_phs[x][2] = io_phs[x][2].replace("bytes:","")
    #io_phs = [["protocol_name", "frames", "bytes"]]+io_phs
    io_phs_dict_list = []
    for x in io_phs:
        temp={
            "protocol_name":x[0],
            "frames":x[1],
            "bytes":x[2]
        }
        io_phs_dict_list.append(temp)

    #print("io_phs: %s \n"%(io_phs))



    # print("conv_tcp")
    conv_tcp = check_output(["tshark","-r",asx_ai_pcap_path,"-n","-q","-z","conv,tcp"])
    # internal_host , external_host, external_port, inbound_frame, inbound_bytes, outbound_frames, outbound_bytes, total_frames, total_bytes, relative_start, duration
    # conv_tcp = re.sub(r"\s+"," ",conv_tcp)
    # print(conv_tcp)
    conv_tcp = re.sub(r"================================================================================\n","",conv_tcp)
    conv_tcp = re.findall(r".*\n",conv_tcp)
    del conv_tcp[0:4]
    for x in range(0, len(conv_tcp)):
        conv_tcp[x] = re.sub(r"\s+"," ",conv_tcp[x])
        conv_tcp[x] = conv_tcp[x].split(" ")
        del conv_tcp[x][1]
        temp_1 = conv_tcp[x][0].split(":")
        temp_2 = conv_tcp[x][1].split(":")

        del conv_tcp[x][0],conv_tcp[x][0]
        conv_tcp[x] = temp_1 + temp_2 + conv_tcp[x]
        del conv_tcp[x][12]
        # print("conv Line :: %s"%conv_tcp[x])

    #conv_tcp = [["host_ip","host_port","external_ip","external_port","download_frames","download_bytes","upload_frames","upload_bytes","total_frames","total_bytes","relative_start","duration"]]+conv_tcp

    conv_tcp_dict_list = []
    for x in conv_tcp:
        temp = {
            "host_ip":x[0],
            "host_port":x[1],
            "external_ip":x[2],
            "external_port":x[3],
            "download_frames":x[4],
            "download_bytes":x[5],
            "upload_frames":x[6],
            "upload_bytes":x[7],
            "total_frames":x[8],
            "total_bytes":x[9],
            "relative_start":x[10],
            "duration":x[11]
        }
        conv_tcp_dict_list.append(temp)
    # for x in range(0, len(conv_tcp)):
    #     print("conv Line :: %s"%conv_tcp[x])
    #print conv_tcp

    # print("conv_udp")
    conv_udp=check_output(["tshark","-r",asx_ai_pcap_path,"-n","-q","-z","conv,udp"])
    #print(conv_udp)
    conv_udp = re.sub(r"================================================================================\n","",conv_udp)
    conv_udp = re.findall(r".*\n",conv_udp)
    del conv_udp[0:4]

    for x in range(0, len(conv_udp)):
        conv_udp[x] = re.sub(r"\s+"," ",conv_udp[x])
        conv_udp[x] = conv_udp[x].split(" ")
        del conv_udp[x][1]
        temp_1 = conv_udp[x][0].split(":")
        temp_2 = conv_udp[x][1].split(":")

        del conv_udp[x][0],conv_udp[x][0]
        conv_udp[x] = temp_1 + temp_2 + conv_udp[x]
        del conv_udp[x][12]
        # print("conv Line :: %s"%conv_udp[x])

    #conv_udp = [["host_ip","host_port","external_ip","external_port","download_frames","download_bytes","upload_frames","upload_bytes","total_frames","total_bytes","relative_start","duration"]]+conv_udp
    conv_udp_dict_list = []
    for x in conv_udp:
        temp = {
            "host_ip":x[0],
            "host_port":x[1],
            "external_ip":x[2],
            "external_port":x[3],
            "download_frames":x[4],
            "download_bytes":x[5],
            "upload_frames":x[6],
            "upload_bytes":x[7],
            "total_frames":x[8],
            "total_bytes":x[9],
            "relative_start":x[10],
            "duration":x[11]
        }
        conv_udp_dict_list.append(temp)

    # for x in range(0, len(conv_udp)):
    #     print("conv Line :: %s"%conv_udp[x])
    # print(conv_udp)


    #-q -z http,tree
    #-q -z http_req,tree
    #-q -z http_srv,tree
    #-q -z io,phs
    #-q -z conv,tcp
    #-q -z conv,udp

    #whitelist ip by quering IPVOID
    #check IP black list and URL and domain balck list on virustotal
    #www.urlvoid.com
    #www.fortiguard.com
    #http://www.alienvault.com/apps/rep_monitor/ip/37.221.161.215
    #

    #-R "!(ip.addr == 64.18.0.0/20) and !(ip.addr == 64.233.160.0/19) and !(ip.addr == 66.102.0.0/20) and !(ip.addr == 66.249.80.0/20) and !(ip.addr == 72.14.192.0/18) and !(ip.addr == 74.125.0.0/16) and !(ip.addr == 108.177.8.0/21) and !(ip.addr == 173.194.0.0/16) and !(ip.addr == 207.126.144.0/20) and !(ip.addr == 209.85.128.0/17) and !(ip.addr == 216.58.192.0/19) and !(ip.addr == 216.239.32.0/19)"
    # -w pcap_ASX.pcap
    # google IP ranges: nslookup -q=TXT _netblocks.google.com 8.8.8.8
    """
    64.18.0.0/20  = !(ip.addr == 64.18.0.0/20)
    64.233.160.0/19  = !(ip.addr == 64.233.160.0/19)
    66.102.0.0/20 = !(ip.addr == 66.102.0.0/20)
    66.249.80.0/20 = !(ip.addr == 66.249.80.0/20)
    72.14.192.0/18 = !(ip.addr == 72.14.192.0/18)
    74.125.0.0/16 = !(ip.addr == 74.125.0.0/16)
    108.177.8.0/21 = !(ip.addr == 108.177.8.0/21)
    173.194.0.0/16 = !(ip.addr == 173.194.0.0/16)
    207.126.144.0/20 = !(ip.addr == 207.126.144.0/20)
    209.85.128.0/17 = !(ip.addr == 209.85.128.0/17)
    216.58.192.0/19 = !(ip.addr == 216.58.192.0/19)
    216.239.32.0/19 = !(ip.addr == 216.239.32.0/19)
    """

    #  http_srv,tree
    # http_req,tree
    return io_phs_dict_list,conv_tcp_dict_list,conv_udp_dict_list


def layer_2_C():
    temp_mdb  = my_mdb()

    virustotal_url = []
    vt_ipvoid_ip = []
    url_list = []
    host_list = []

    temp_hash_list = []
    temp_mdb.cl_analysis_tickets.find().batch_size(1)
    results = temp_mdb.cl_analysis_tickets.find({"current_analysis_layer":{"$in":["layer_2C","layer_3","layer_3A","layer_3A_1"]}})
    #print(red("-----Debug"))

    if results.count() == 0:
        print(yellow("No layer 2C analysis pending"))
        return
    try:
        for each in results:
            del temp_hash_list[:]
            try:
                print (cyan("\nTime now: %s\n")%(time.strftime("%Y-%m-%D :: %H:%M:%S")))
                ticket = objects_ASX.ticket(each)

                print(green("Working on ticket_ID :: %s"%(ticket.ticket_id)))
                required_network_data = temp_mdb.cl_analysis.find_one({"target.file.sha256":ticket.hash_sha256},{"network.hosts":1,"droidmon.httpConnections.request":1})
                #print "lsit of hosts: %s"%(required_network_data)

                del virustotal_url[:]
                del vt_ipvoid_ip[:]
                del url_list[:]
                del host_list[:]


                if len(required_network_data["droidmon"]) != 0:
                    for x in required_network_data["droidmon"]['httpConnections']:

                        #erororr : if the x in empty
                        try:
                            x['request'] = x['request'].split(" ") # gives list with method,req,HTTP version, so actual req is at index 1
                            x['request'][1] = x['request'][1].encode(encoding='utf-8',errors='ignore')
                        except:
                            continue
                        print(red("---Debug :: %s"%(x['request'][1])))
                        print(red("---Debug Unicode :: %s"%(x['request'][1])))
                        #str.encode(encoding='ascii',errors='ignore')
                        temp_1 = temp_mdb.cl_analyzed_url_ip.find_one({"hash":hashlib.sha256(x['request'][1]).hexdigest()})
                        if temp_1 == None and (hashlib.sha256(x['request'][1]).hexdigest() not in temp_hash_list):
                            url_list.append(x['request'])
                            temp_hash_list.append(hashlib.sha256(x['request'][1]).hexdigest())
                        else:
                            if(hashlib.sha256(x['request'][1]).hexdigest() in temp_hash_list):
                                print(green("Resource is already queued for analysis: %s"%(x['request'][1])))
                                continue
                                # I have made a fair assumption that I will run this layer 2c twice
                                # and in next iteration I will get the already analyzed url
                            else:
                                print(green("Resource already analyzed: %s"%(x['request'][1])))
                                virustotal_url.append(temp_1["result"])

                if len(required_network_data["network"]) != 0:
                    for y in required_network_data['network']['hosts']:
                        # print(hashlib.sha256(y).hexdigest())
                        temp_1 = temp_mdb.cl_analyzed_url_ip.find_one({"hash":hashlib.sha256(y).hexdigest()})
                        if (not trusted_ip(y)) and (temp_1 == None) and (hashlib.sha256(y).hexdigest() not in temp_hash_list):
                            host_list.append(y)
                            temp_hash_list.append(hashlib.sha256(y).hexdigest())
                        else:
                            if temp_1 != None:
                                if (hashlib.sha256(y).hexdigest() in temp_hash_list):
                                    print(green("Resource is already queued for analysis: %s"%(y)))
                                    continue
                                else:
                                    print(green("Resource already analyzed: %s"%(y)))
                                    vt_ipvoid_ip.append(temp_1["result"])
                # print("URL: %s"%(url_list))
                # print("Hosts: %s"%(host_list))





                if len(url_list)!=0:
                    temp_2 =0
                    for url in url_list:
                        if temp_2 == 4:
                            print(yellow("------Sleeping 65 sec------"))
                            time.sleep(65)
                            temp_2 = 0
                        virustotal("url_scan",url[1])
                        print(yellow("------Sleeping 5 sec------"))
                        time.sleep(5)
                        temp_2+=1
                        #temp_hash_list.append(hashlib.sha256(url[1]).hexdigest())

                    for url in url_list:
                        if temp_2 >= 4:
                            print(yellow("------Sleeping 65 sec------"))
                            time.sleep(65)
                            temp_2 = 0
                        vt_row = {"url":{"method":url[0],"resource":url[1],"HTTP_V":url[2]},"vt_result":virustotal("url_report",url[1]).result}
                        print(yellow("------Sleeping 5 sec------"))
                        time.sleep(5)
                        virustotal_url.append(vt_row)
                        temp_mdb.cl_analyzed_url_ip.insert({"hash":hashlib.sha256(url[1]).hexdigest(),"result":vt_row})
                        #temp_hash_list.append(hashlib.sha256(url[1]).hexdigest())
                        temp_2+=1
                        # print(vt_row)



                if len(host_list)!=0:
                    print(yellow("------Sleeping 60 sec------"))
                    time.sleep(60)
                    for host in host_list:
                        row = {"host_ip":host,"vt_result":virustotal("ip",host).result,"ipvoid_result":ipvoid(host).ip_void_info}
                        print(yellow("------Sleeping 25 sec------"))
                        time.sleep(25)
                        vt_ipvoid_ip.append(row)
                        temp_mdb.cl_analyzed_url_ip.insert({"hash":hashlib.sha256(host).hexdigest(),"result":row})
                        #temp_hash_list.append(hashlib.sha256(host).hexdigest())


                        # print(row)
                temp_result = temp_mdb.cl_vt_ipv_results.find({"file_hash_sha256":ticket.hash_sha256})
                if temp_result.count() != 0:
                    temp_mdb.cl_vt_ipv_results.update({"file_hash_sha256":ticket.hash_sha256},{"$set":{"ticket_id":ticket.ticket_id,"cuckoo_id":ticket.cuckoo_id,"cuckoo_folder_id":ticket.cuckoo_folder_id,"vt_url_scan":virustotal_url,"vt_ipvoid_ip":vt_ipvoid_ip}})
                else:
                    temp_mdb.cl_vt_ipv_results.insert({"ticket_id":ticket.ticket_id,"file_hash_sha256":ticket.hash_sha256,"cuckoo_id":ticket.cuckoo_id,"cuckoo_folder_id":ticket.cuckoo_folder_id,"vt_url_scan":virustotal_url,"vt_ipvoid_ip":vt_ipvoid_ip})
                if ticket.current_analysis_layer == "layer_2C":
                    temp_mdb.cl_analysis_tickets.update({"ticket_id":ticket.ticket_id},{'$set':{"current_analysis_layer":"layer_3"}})
                elif ticket.current_analysis_layer == "layer_3":
                        temp_mdb.cl_analysis_tickets.update({"ticket_id": ticket.ticket_id},{'$set': {"current_analysis_layer": "layer_3A"}})
                elif ticket.current_analysis_layer == "layer_3A":
                        temp_mdb.cl_analysis_tickets.update({"ticket_id": ticket.ticket_id},{'$set': {"current_analysis_layer": "layer_3A_1"}})

                elif ticket.current_analysis_layer == "layer_3A_1":
                    temp_mdb.cl_analysis_tickets.update({"ticket_id": ticket.ticket_id},{'$set': {"current_analysis_layer": "layer_3A_2"}})
                else:
                    print(red("Error in 2C"))
                    exit()
                # get list of hosts : network.hosts
                # get list of hosts : network.dns.request -- this is domain
                # get list of hosts : network.domains
                # get list of hosts : network.domains


                # temp_mdb.cl_analysis.update({"target.file.sha256":ticket.hash_sha256},{'$set':{"input_output_protocol_hirarchy":io_phs,"tcp_conversation":conv_tcp,"udp_conversation":conv_udp}})
            except:
                traceback.print_exc()
                print ("\n\nError ticket details: \n%s ::\nvt_url_scan:%s \nvt_ipvoid_ip:%s"%(ticket.ticket_id,virustotal_url,vt_ipvoid_ip))
                continue

    except:
        traceback.print_exc()
        print ("\n\nError ticket details: \n%s ::\nvt_url_scan:%s \nvt_ipvoid_ip:%s" % (
        ticket.ticket_id, virustotal_url, vt_ipvoid_ip))
        #exit()

    temp_mdb.close()

def trusted_ip(ip):
    trusted_ranges = ['64.18.0.0/20', '64.233.160.0/19','66.102.0.0/20','66.249.80.0/20','72.14.192.0/18','74.125.0.0/16','108.177.8.0/21', '173.194.0.0/16', '207.126.144.0/20', '209.85.128.0/17', '216.58.192.0/19', '216.239.32.0/19','8.8.8.8/32','8.8.4.4/32']
    network_range_list = []
    for each in trusted_ranges:
        network_range_list.append(netaddr.IPNetwork(each))

    for each in network_range_list:
        if netaddr.IPAddress(ip) in list(each):
            return True
    return False



import simplejson
import urllib
import urllib2

class virustotal(object):
    total_vt_query = 0
    url_scan = "https://www.virustotal.com/vtapi/v2/url/scan"
    url_report = "https://www.virustotal.com/vtapi/v2/url/report"
    ip_report = "https://www.virustotal.com/vtapi/v2/ip-address/report"

    def __init__(self,url_or_ip,parameter):

        self.result = None
        # if virustotal.total_vt_query > 5000:
        #     print(red("\n\n Daily VT limit reached"))
        #     exit()
        # else:
        print("Total VT query in this pass : %s"%(virustotal.total_vt_query))
        #----------------------------------------------------------
        if url_or_ip == 'url_report':
            self.parameter = {"resource":parameter,
                          "apikey":Purposefully_added_error} #add your personal VT key
            self.data = urllib.urlencode(self.parameter)
            self.req = urllib2.Request(self.url_report,self.data)
            virustotal.total_vt_query +=1
            try:
                self.response = urllib2.urlopen(self.req)
                print("Self Response :%s"%(self.response.info()))
                #if self.response.info().getheader(''):

            except urllib2.HTTPError as e:
                http_error_code = e.code
                http_error_msg = e.read()
                print(red("HTTP Error:\nURL:%s \n\nCode:%s\nResponse:%s"%(parameter,http_error_code,http_error_msg)))
                exit()

            self.json = self.response.read()
            try:
                self.result = simplejson.loads(self.json)
            except:
                self.result={
                'response_code' : 0,
                'verbose_msg' : "Attempt to fetch result failed "
                }

            if self.result['response_code'] == -1:
                print(red("Error for: %s\n%s")%(parameter,self.result))
                # exit()
            '''
            if self.result== None:
                self.result={
                'response_code' : 0,
                'verbose_msg' : "Attempt to fetch result failed "
                }
            '''

            # {
            # "scan_date":
            # "scan_id":
            # "filescan_id":
            # "positives":
            # "total":
            # "permalink":
            # "resource":
            # "url":
            # "response_code":
            # "verbose_msg":
            # "scans":
            # }

            # {
            # 'response_code':,
            # 'resource':,
            # 'verbose_msg': 'The requested resource is not among the finished, queued or pending scans'}
        #----------------------------------------------------------
        if url_or_ip == 'url_scan':
            print("Submitting URL for scan")
            self.parameter = {"url":parameter,
                      "apikey":Purposefully_added_error} #add your personal VT key
            self.data = urllib.urlencode(self.parameter)
            self.req = urllib2.Request(self.url_scan,self.data)
            virustotal.total_vt_query +=1
            try:
                self.response = urllib2.urlopen(self.req)
            except urllib2.HTTPError as e:
                http_error_code = e.code
                http_error_msg = e.read()
                print(red("HTTP Error:\nURL:%s \n\nCode:%s\nResponse:%s"%(parameter,http_error_code,http_error_msg)))
                return
            self.json = self.response.read()
            try:
                self.result = simplejson.loads(self.json)
            except:
                self.result={
                'response_code' : 0,
                'verbose_msg' : "Attempt to fetch result failed "
                }

            if self.result['response_code'] == -1:
                print(red("Error for: %s\n%s")%(parameter,self.result))
                # exit()




        #-----------------------------------------------------------
        if url_or_ip == 'ip':
            self.parameter = {'ip':str(parameter),
                              "apikey":Purposefully_added_error} #add your personal VT key
            # print("%s?%s"%(self.ip_report,urllib.urlencode(self.parameter)))
            self.response_1 = urllib.urlopen("%s?%s"%(self.ip_report,urllib.urlencode(self.parameter)))
            virustotal.total_vt_query +=1
            self.response = self.response_1.read()
            print("HTTP reaponse code: %s"%(self.response_1.getcode()))
            try:
                self.result = simplejson.loads(self.response)
            except:
                print("Error in url_or_ip for : %s"%(parameter))

                print(yellow("------Sleeping 25 sec------"))
                time.sleep(25)

                print(yellow("Making another attempt"))
                try:
                    self.response_1 = urllib.urlopen("%s?%s"%(self.ip_report,urllib.urlencode(self.parameter)))
                    virustotal.total_vt_query +=1
                    self.response = self.response_1.read()
                    self.result = simplejson.loads(self.response)
                except:
                    print(self.response)
                    print("Error in url_or_ip 2nd time for : %s"%(parameter))
                    self.result={
                        'response_code' : 0,
                        'verbose_msg' : "Attempt to fetch result failed"
                        }


            if self.result['response_code'] == -1:
                print(red("Error for: %s\n%s")%(parameter,self.result))
                exit()

        if 'scans' in self.result.keys():
            # self.result['scans'] = str(self.result['scans'])
            self.result.pop("scans",None)#scan details are of no use

        if self.result['response_code'] == 1:
            print(green("-----Ok-----"))
            #print(green(self.result))
        else:
            print(red(self.result))



ip_void_temp = []
class ipvoid(object):
    url = "http://www.ipvoid.com/scan/"
    global ip_void_temp
    def __init__(self, ip_adress):
        self.ip_address = str(ip_adress)
        self.analysis_date= None
        self.blacklist_status=None
        self.reverse_DNS=None
        self.ASN=None
        self.ASN_owner=None
        self.ISP=None
        self.continent=None
        self.country_code=None
        self.latitude_longitude=None
        self.city=None
        self.region=None



        self.req = urllib2.Request(self.url+self.ip_address)
        self.response = urllib2.urlopen(self.req)
        self.html_page = self.response.read()




        self.ipvoid_html_pars = ipvoid_parser()


        self.ip_void_info = {"Blacklist Status": 0, "IP Address":self.ip_address}

        try:
            self.get_ipVoid_results()
        except:
            print ("Issue in fetching IPvoid info for IP :%s"%(self.ip_address))
            traceback.print_exc()




    def get_ipVoid_results(self):
        try:
            req = urllib2.Request(self.url+self.ip_address)
            try:
                response = urllib2.urlopen(req)
            except urllib2.HTTPError as e:
                response = e.msg
                print(red("Error in IPvoid : %s :: Error code : %s"%(self.ip_address,e.code)))
                print(yellow("------Sleeping 20 sec------"))
                time.sleep(20)
                print(yellow("------IPvoid 2nd attempt------"))
                try:
                    response = urllib2.urlopen(req)
                except urllib2.HTTPError as e:
                    print(red("Error in IPvoid 2nd time: %s :: Error code : %s"%(self.ip_address,e.code)))
                    traceback.print_exc()
                #exit()
            html_page = response.read()
            try:
                temp_html = re.search(r"\<h.*?IP\sAddress\sInformation(.|\n)*?</tbody>",html_page).group(0)
                data_table = re.findall(r"<tr>.*?</tr>",temp_html,re.IGNORECASE)
                for x in data_table:
                    x = str(x)

                    if x.find("Analysis Date")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []



                    if x.find("Blacklist Status")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        if ip_void_temp[1].find("BLACKLISTED")!=-1:
                            temp = str(ip_void_temp[1])
                            temp = temp.replace("BLACKLISTED","")
                            temp = temp.replace(" ","")
                            self.ip_void_info["Blacklist Status"]=temp

                        if ip_void_temp[1].find("POSSIBLY SAFE")!=-1:
                            temp = str(ip_void_temp[1])
                            temp = temp.replace("POSSIBLY SAFE","")
                            temp = temp.replace(" ","")
                            self.ip_void_info["Blacklist Status"]=temp

                        self.ip_void_info["Blacklist Status"] = re.sub(r"\/.*","",self.ip_void_info["Blacklist Status"])

                        ip_void_temp[:] = []


                    if x.find("IP Address")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []


                    if x.find("Reverse DNS")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []


                    if x.find("ASN")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []


                    if x.find("ASN Owner")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []


                    if x.find("ISP")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []


                    if x.find("Continent")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []


                    if x.find("Country Code")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []


                    if x.find("Latitude / Longitude")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []



                    if x.find("City")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []


                    if x.find("Region")!=-1:
                        self.ipvoid_html_pars.feed(x)
                        self.ip_void_info[ip_void_temp[0]]=ip_void_temp[1]
                        ip_void_temp[:] = []

                    else:
                        pass
            except:
                self.ip_void_info = {"Blacklist Status": 0, "IP Address":self.ip_address}



            # print self.ip_void_info
            # print "\n\n------------------------------------->>>\n"
        except:
            print(red("Error in IP info :: %s :: \n Webpasge:\n%s"%(self.ip_address,html_page)))
"""
I want to store data as following dict struct:
{
    "ip_address_information":
    {
        "analysis_date":None,
        "blacklist_status":None,
        "ip_address":None,
        "reverse_DNS":None,
        "ASN":None,
        "ASN_owner":None,
        "ISP":None,
        "continent":None,
        "country_code":None,
        "latitude_longitude":None,
        "city":None,
        "region":None
    },
    "ip_blacklist_report":list_of_report[]
    #list_of_report is meant to
}
"""

class ipvoid_parser(HTMLParser):
    global ip_void_temp
    def handle_starttag(self, tag, attrs):
        pass
    def handle_data(self, data):
        ip_void_temp.append(data)
    def handle_endtag(self, tag):
        pass

import sys
import datetime
if __name__=="__main__":

    
    if len(sys.argv)!=2:
        print(red("!!! >>>>: Wrong Input :<<<< !!!"))
        exit()

    input_temp = sys.argv[1]

    if input_temp == '1':
        layer_2_A()
        print(green("\n\n>>>>:: Layer 2A ended"))
        exit()
    if input_temp == '2':
        layer_2_B()
        print(green("\n\n>>>>:: Layer 2B ended"))
        exit()
    if input_temp == '3':
        while True:
            try:
                layer_2_C()
                print(green("\n\n>>>>:: Layer 2c ended hit cntrl c  if yo uwant in next 5 sec"))
                time.sleep(5)
            except:
                exit()

    if input_temp == 'auto':
        while True:
            try:
                layer_2_A()
                print(green("\n\n>>>>:: Layer 2A ended"))
                layer_2_B()
                print(green("\n\n>>>>:: Layer 2B ended"))
                layer_2_C()
                print(green("\n\n>>>>:: Layer 2c ended"))
                layer_2_C()
                print(green("\n\n>>>>:: Layer 2c ended 2nd time"))
                print(yellow("------Sleeping 65 sec------"))
                time.sleep(65)
            except:
                traceback.print_exc()
                print(green("\n\n>>>>:: Auto ended"))
                exit()
    if input_temp == 'test':
        print(green("\n\n>>>>:: Test ended"))
        exit()

    print(red("!!! >>>>: Wrong Input :<<<< !!!"))

    pass
