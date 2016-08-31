#snort analysis
from os import path
import subprocess
import re
from util.color import *
import objects_ASX
import mongodb_ASX
import shutil
import os
import time
from multiprocessing import Pool
from util.color import red, green
import traceback

def execute_snort():
    temp_mbd = mongodb_ASX.my_mdb()
    results = temp_mbd.cl_analysis_tickets.find({"current_analysis_layer":"layer_3A_2"}) #"layer_4A"})
    if results.count() == 0:
        print("All the applications completed Snort // result empty")
    else:
        pool_of_threads = Pool(10)
        for each in results:
            ticket = objects_ASX.ticket(each)
            if temp_mbd.cl_analysis.find_one({"target.file.sha256":ticket.hash_sha256}) != None:
                pool_of_threads.apply_async(snort_exec_thread,args=(ticket,),callback=None)
                # snort_exec_thread(ticket)
            # NO need of this as its done in funtion
            # temp_mbd.cl_analysis_tickets.update({"ticket_id":ticket.ticket_id},{"$set":{"current_analysis_layer":"layer_4A"}})
            else:
                print green("Ticket_id: %s Dont have droidmon.httpConnections"%(ticket.ticket_id))
        pool_of_threads.close()
        pool_of_threads.join()

def snort_exec_thread(ticket):
    temp_mbd = mongodb_ASX.my_mdb()
    asx_folder_path = (os.path.split(os.path.abspath(__file__)))[0]
    app_folder_path = os.path.join(asx_folder_path,"cuckoo","storage","analyses",str(ticket.cuckoo_folder_id))
    pcap_path = os.path.join(app_folder_path,"dump.pcap")
    snort_folder_path =  os.path.join(app_folder_path,"snort_logs")
    snort_log_file_path = os.path.join(snort_folder_path,"alert")

    if os.path.exists(snort_folder_path):
        shutil.rmtree(snort_folder_path)
        os.mkdir(snort_folder_path)
    else:
        os.mkdir(snort_folder_path)

    if os.path.exists(snort_log_file_path):
        os.remove(snort_log_file_path)


    subprocess.call(["snort", "-r", pcap_path, "-c", "/etc/snort/snort.conf", "-K","ascii", "-l", snort_folder_path, "-A", "full"])

    ticket.current_analysis_layer = "layer_3_snort_exc"

    # ***Need some delay here
    try:
        while True:
            if os.path.exists(snort_log_file_path):
                time.sleep(20)
                log_file = open(snort_log_file_path,'r')
                print green("snort_log_file successfully red for ticket_id : %s" % (ticket.ticket_id))
                time.sleep(1)
                break

            else:
                print red("snort_log_file not yet found sleeping 20 sec for ticket_id : %s"%(ticket.ticket_id))
                time.sleep(20)

    except:
        print (red("Error in ticket_id: %s"%(ticket.ticket_id)))
        traceback.print_exc()
        time.sleep(10)
        exit()


    log_dict = {"sid_gid":None,"summary":None,"Classification":None,"Priority":None,"time_stamp":None,"srcIP":None,"dstIP":None}
    snort_logs = []
    count = 1
    for x in log_file.readlines():


        print yellow("Parsing Line: Count:%s : %s"%(count,x))
        if re.search(r"\[\d*:\d*:\d*\]", x) == None and re.search(r"\[Classification:.*?\]", x) == None:
            continue
        # if count == 3:
        #     snort_logs.append(log_dict)
        #     log_dict = {"sid_gid": None, "summary": None, "Classification": None, "Priority": None, "time_stamp": None,
        #                "srcIP": None, "dstIP": None}
        #     count = 1
        #
        #     continue #skiping every 6th line
        elif count == 1:
            #[**] [129:15:1] Reset outside window [**]
            temp = x.replace("[**]","")


            log_dict["sid_gid"]=re.findall(r"\[\d*:\d*:\d*\]",temp)[0]
            # log_dict["sid_gid"]=re.search(r"\[\d*:\d*:\d*\]",temp).group(0)


            temp=re.sub(r"\[\d*:\d*:\d*\]\s+","",temp)
            log_dict["summary"]=temp.replace("\n","")
            count += 1

            # print log_dict["sid_gid"]
            # print log_dict["summary"]

        elif count == 2:
            #[Classification: Potentially Bad Traffic] [Priority: 2]
            temp = re.findall(r"\[Classification:.*?\]",x)[0]
            #temp = re.search(r"\[Classification:.*?\]",x).group(0)
            log_dict["Classification"]=temp.replace("[","").replace("]","").replace("Classification: ","")
            temp = re.findall(r"\[Priority:.*?\]", x)[0]
            log_dict["Priority"]=temp.replace("[","").replace("]","").replace("Priority: ","").replace("\n","")


            snort_logs.append(log_dict)

            print green("Parsed Log:: %s"%(log_dict))
            log_dict = {"sid_gid": None, "summary": None, "Classification": None, "Priority": None, "time_stamp": None,
                        "srcIP": None, "dstIP": None}
            count = 1

            # print log_dict["Classification"]
            # print log_dict["Priority"]

        # elif count == 3:
        #     #05/07-01:32:12.657362 192.168.56.11:44207 -> 74.125.138.188:5228
        #     temp = x.split(" ")
        #     log_dict["time_stamp"]=temp[0]
        #     log_dict["srcIP"]=temp[1]
        #     log_dict["dstIP"]=temp[3].replace("\n","")


        # elif count==4:
        #     #TCP TTL:64 TOS:0x20 ID:27795 IpLen:20 DgmLen:40 DF
        #     pass # no need of this data at this point
        # elif count==5:
        #     #*****R** Seq: 0x2E48D8C3  Ack: 0x0  Win: 0x0  TcpLen: 20
        #     pass # no need of this data at this point



    if temp_mbd.cl_pcap_snort_log.find_one({"hash_sha256":ticket.hash_sha256}) == None:
        temp_mbd.cl_pcap_snort_log.insert({"hash_sha256":ticket.hash_sha256,"ticket_id":ticket.ticket_id,"cuckoo_folder_id":ticket.cuckoo_folder_id,"snort_logs":snort_logs})
    else:
        temp_mbd.cl_pcap_snort_log.update({"hash_sha256":ticket.hash_sha256},{"$set":{"ticket_id":ticket.ticket_id,"cuckoo_folder_id":ticket.cuckoo_folder_id,"snort_logs":snort_logs}})

    #print snort_logs
    print ticket.give_dict()
    temp_mbd.cl_analysis_tickets.update({"hash_sha256": ticket.hash_sha256},
                                        {"$set": {"current_analysis_layer": "layer_3_snort_exc"}})

def snort_exec_thrd_return(ticket):
    pass
    #snort_output = re.search(r"Commencing packet processing (.|\n)*?Snort exiting",str(snort_output)).group(0)

#snort -r /media/suyash/suyash_sshd/storage/analyses/6/dump.pcap -c /etc/snort/snort.conf -K ascii -l /media/suyash/suyash_sshd/storage/analyses/6/snort_logs/ -A full
#
# [**] [129:15:1] Reset outside window [**]
# [Classification: Potentially Bad Traffic] [Priority: 2]
# 05/07-01:32:12.197929 183.61.185.84:25 -> 192.168.56.11:35252
# TCP TTL:199 TOS:0x20 ID:10767 IpLen:20 DgmLen:40 DF
# ***A*R** Seq: 0x9E67AB07  Ack: 0x1AAE185F  Win: 0x1114  TcpLen: 20


if __name__=='__main__':
    '''
    ticket = {
            "ticket_id" : 6,
            "cuckoo_id":None,
            "file_path":None,
            "hash_sha256":"d966abc28b0a25f3303762bb47b1e75eb78e23f0c0681312bd46f20faed4bdf8",
            "android_app_name":None,
            "android_package_name":None,
            "time_submission":None,
            "current_analysis_layer":"layer_3A_1",
            "ai_feature":{},
            "snort_signatures":{},
            "ai_decision":{},
            "report":{},
            "analysis_end_time":None,
            "analysis_status":'incomplete',
            "cuckoo_folder_id":6,
            "analysis_start_time":None,
            "apktool_data_path": None
        }
    snort_exec_thread(objects_ASX.ticket(ticket))
    '''
    execute_snort()


