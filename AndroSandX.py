#!/usr/bin/python

####import section#####
from util.color import *
import layer_1
import cuckoo
import sys

import error_reporting as error
from mongodb_ASX import my_mdb
from collections import deque
from objects_ASX import ticket, token, global_var
import datetime
import hashlib
import os
import time
####end of import section ####


'''
This is a complete analysis module which will start with a ticket creations
1. Create a analysis ticket with unique ID + ticket initial variable
2. Create a mondodb collection of completed tickets
3. Create a collection of queued analysis
4. Object ticket is passed from layer to layer
5. Each layer has its one collection of queued tickets
6.




Layers:
1. Get a analysis request
2. Perform cuckoo analysis for the submitted application
3. Feature extration layer
4.  a. AI decision making layer /
    b. AI model training layer
5. Reporting layer /
6. Manual analysis + Snort signature creation layer
7. Snort signature testing layer
8. Manual Analysis reporting layer

'''







global_var = global_var()
db_var = my_mdb()
training_or_analyze = None
#### function area ####




def start_asx(file_apk):
    if not global_var.global_var_initialized:
        #initialize global var
        global_var.global_var_initialized = init_global_var()
        #initializing global token queue

    # print("Global New Queue Length ::",len(global_var.global_new_ticket_queue))
    create_new_ticket(file_apk)
    # print("globnewqu :: ",len(global_var.global_new_ticket_queue))

    # print("Global layer 1 Queue lenght :: ",len(global_var.global_layer1_queue))
    # send_ticket_to_layer_1()
    # # print("glob layer 1 :: ",len(global_var.global_layer1_queue))

    # print green("Tranferring control to layer 1")
    #layer_1.layer_1_analysis()


    #analysis_req_1 = layer_1.cuckoo_analysis_req(file_apk)

def create_new_ticket(file_path):
    global training_or_analyze
    temp_ticket = ticket(None)
    temp_ticket.file_path = os.path.abspath(file_path)
    temp_ticket.analysis_start_time = datetime.datetime.utcnow()
    temp_ticket.hash_sha256 = hash_calculator(temp_ticket.file_path)
    global_var.current_ticket_id +=1
    temp_ticket.ticket_id = global_var.current_ticket_id
    temp_ticket.analysis_status = "new"
    temp_ticket.current_analysis_layer = "layer_0"
    temp_ticket.ai_decision = {"data":[],"analysis_conclusion":training_or_analyze}

    global_var.global_var_update()
    # global_var.global_new_ticket_queue.append(temp_ticket)

    my_mdb().cl_new_tickets.insert(temp_ticket.give_dict())
    # return temp_ticket
    #temp_ticket.hash_sha256 = pass
    # http://stackoverflow.com/questions/3431825/generating-a-md5-checksum-of-a-file
    ##

def send_ticket_to_layer_1():  #function not in use
    while True:
        if len(global_var.global_layer1_queue) > 10:
            print yellow(">>> Layer 1 queue is having more than 10 events waiting for arorund 4 minutes")
            time.sleep(240)
        else:
            for x in range(0,5):
                if len(global_var.global_new_ticket_queue) == 0:
                    print green(">>> New ticket queue empty")
                    return
                print s_violet("Sending ticket to layer 1 queue")
                tmp = global_var.global_new_ticket_queue.popleft()
                global_var.global_layer1_queue.append(tmp)
                my_mdb().cl_new_tickets.remove({'ticket_id':tmp.ticket_id})


def hash_calculator(file_path):
    hash_sha256 = hashlib.sha256()
    file_temp =  open(file_path,'rb')
    buff = file_temp.read(65536)
    while len(buff) > 0:
        hash_sha256.update(buff)
        buff = file_temp.read(65536)
    return hash_sha256.hexdigest()


def init_global_var():

    # creating db var
    db_var = my_mdb()

    #using find_one // it return dict
    temp_result = db_var.cl_static_var.find_one()

    # global_var.current_token_id = temp_result['current_token_id']
    global_var.current_ticket_id = temp_result['current_ticket_id']


    temp_result = db_var.cl_new_tickets.find()
    for row in temp_result:
        global_var.global_new_ticket_queue.append(ticket(row))



    if len(global_var.global_new_ticket_queue)!=0:
        print "Queud global_new_ticket_queue:: ",global_var.global_new_ticket_queue[0].ticket_id

    print "Globla var // ",global_var


    return True
    #

    #initialize a global token and ticket queue


def get_netflow_data():
    pass

def get_apktool_data():
    pass

#### end of function area ####



#### Main entry point of script ####

if __name__ == "__main__":

    # parameter(file_path,malware/benign)
    print cyan("~~~~~ Welcome to AndroSandX ~~~~~").center(50)
    print cyan("~~~~~ I hope you love AndroSandX ~~~~~").center(50)
    if len(sys.argv)!=3:
        print(green("Wrong input"))
        exit()
    path = sys.argv[1]
    training_or_analyze = str(sys.argv[2])

    print(path)
    print(training_or_analyze)
    if training_or_analyze not in ('malware','benign','analyze_m','analyze_b'):
        print(red("Wrong input"))
        exit()

    start_point = 0
    max_appps_to_analyze = 2000
    count = 0
    for (dir_path, dir_name, file_name) in os.walk(path):
        for x in file_name:
            if count >= max_appps_to_analyze:
                print("Count reached max")
                exit()
            if count < start_point:
                print("Skiped App number: %s"%(count))
                count+=1
                continue
            file_temp = os.path.join(dir_path,x)
            print green("Count : ") + str(count) + "\n" + str(file_temp)
            start_asx(file_temp)
            count+=1
    # start_asx(sys.argv[1])
    #create_new_ticket(sys.argv[1])
    #start_asx()
    #layer_1.layer_1_analysis()


#### End of this file

