
#layer 1 : functions
#1. take primary analysis req,
#2. create a primary token, global token_id++ and add to global_incomplete_token
#3. create a global analysis ticket add to global_new_tickets
# once
# get a analysis id from global static var, increment

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
import thread

layer_1_global_var = objects_ASX.global_var()

class cuckoo_analysis_req(object):
    def __init__(self, file_apk):
        self.target = file_apk
        self.debug = None
        self.remote = None
        self.url = None
        self.custom = None
        self.package = None
        self.timeout = 0
        self.options = None
        self.priority = 1
        self.machine = None
        self.platform = None
        self.memory = False
        self.enforce_timeout = False
        self.clock = None
        self.tags = None
        self.max =  None
        self.pattern = None
        self.shuffle = False
        self.unique = False
        self.quiet = False

######submit.main(analysis_req_1)

def layer_1_new_ticket_watcher():

    try:
        l_db_var = my_mdb()
        new_tickets = None
        new_tickets = l_db_var.cl_new_tickets.find({"current_analysis_layer":"layer_0","analysis_status":"new"})
        if new_tickets.count() == 0:
            print("No new tickets")
            return

        else:
            for x in new_tickets:
                new_ticket = objects_ASX.ticket(x)
                l_db_var.cl_new_tickets.remove({"ticket_id":new_ticket.ticket_id})
                # layer_1_global_var.global_layer1_queue.append(new_ticket)
                temp = l_db_var.cl_analysis_tickets.find_one({"hash_sha256":new_ticket.hash_sha256})
                if temp != None:
                    print(yellow("APK with following hash is already analyzed: %s"%(new_ticket.hash_sha256)))
                    continue
                new_ticket.current_analysis_layer = "layer_1"
                new_ticket.analysis_status = "new"
                l_db_var.cl_analysis_tickets.insert(new_ticket.give_dict())
                print(magenta("Created analysis ticket with id: %s"%(new_ticket.ticket_id)))
    except KeyboardInterrupt:
        print("In except")
        return




def layer_1_init():
    local_db_var = my_mdb()
    result = local_db_var.cl_analysis_tickets.find({"current_analysis_layer":"layer_1"})

    if result.count() == 0:
        print ("No tickets pending layer one analysis")
    else:
        for each in result:
            if each == None:
                print("Layer 1 init found no tickets")
            # print("Each: %s"%(each))
            temp_ticket = objects_ASX.ticket(each)
            layer_1_global_var.global_layer1_queue.append(temp_ticket)

        # print("sss")

    #current_token_id = my_mdb.cl_static_var.findOne()

def layer_1_req(apk_file_path): #function not in use
    layer_1_init()


def layer_1_analysis():
    #temp_ticket = objects_ASX.ticket(None)
    temp_queue = deque()
    temp_mdb = my_mdb()
    print yellow("---------------- I am entering a layer 1 Sandbox batch analysis ----------------")
    #cuckoo.cuckoo_init()
    #cuckoo.cuckoo_main()
    while True:
        try:
            while(len(layer_1_global_var.global_layer1_queue)!=0):
                for x in range(0,8): # change this to 10 if more instance are required
                    if len(layer_1_global_var.global_layer1_queue) == 0:
                        continue
                    print yellow("Total ticket in layer 1 queue:%s"%(len(layer_1_global_var.global_layer1_queue)))
                    ticket = layer_1_global_var.global_layer1_queue.popleft()
                    if my_mdb().cl_analysis_tickets.find_one({'hash_sha256':ticket.hash_sha256,"current_analysis_layer":"layer_1","analysis_status":{"$ne":"new"}}) == None:
                        print s_violet("Submitting cuckoo analysis : Time_now :  %s"%(time.strftime("%Y-%m-%d :: %H:%M:%S")))
                        submit.main(cuckoo_analysis_req(ticket.file_path))
                        print(yellow("------Sleeping 20 sec------"))
                        time.sleep(15)
                        temp_queue.append(ticket) # used in next loop
                        # print "temp_queue  len: ", len(temp_queue)
                    else:
                        print "Already analyzed : hash ", ticket.hash_sha256
                        temp_mdb.cl_analysis_tickets.update({"ticket_id": ticket.ticket_id},{'$set': {"current_analysis_layer": "layer_2A"}})

                print magenta(">>>> :) Going to Sleep for 3 min till the Analysis batch is completed :) <<<<")
                time.sleep(180)
                #send this batch to next layer
                # temp_queue.append(ticket) # used in next loop
                for x in range(0, len(temp_queue)):
                    ticket = temp_queue.popleft()
                    temp_mdb.cl_analysis_tickets.update({"ticket_id":ticket.ticket_id},{'$set':{"current_analysis_layer":"layer_2A"}})

            if len(layer_1_global_var.global_layer1_queue) == 0:
                print yellow("~~~~~Layer 1 Queue is empty~~~~~")
                print(green("\n\n>>>>:: Layer 1 ended"))
                return
            else:
                print green("~~~~~Got some events in the Queue running next batch of Sandbox Analysis~~~~~")

        except KeyboardInterrupt:
            print cyan(">> Cought KeyboardInterrupt <<")
            raw_input()





'''
How to debug android application:
1st use apktool to decompile and then recompile with in debug mode get the apk sign it using bellow given tools. Import the decompiled folder in android studio and switch to project view and make smali as project content root/ onece done that get the expecting we have already installed the signed apk. Now start the adbm(monitor) and andorid device running we can fins the specific applicaton packagename listed, select it and note the port to comunicate, not create a new bebugger in the studio, use option "attach" and correct port. And thats it we are good to go set the break point and run the application, it will stop at the break point.


Signing of application:
keytool -genkey -v -keystore suyash_key_store.keystore -alias suyash_key -keyalg RSA -keysize 2048 -validity 10

jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore suyash_key_store.keystore /media/suyash/suyash_nas_1/AndroSandX_current/storage/analyses/1/apktool/dist/Gentle_WakeupAlarm.apk suyash_key

jarsigner -verify -verbose -certs /media/suyash/suyash_nas_1/AndroSandX_current/storage/analyses/1/apktool/dist/Gentle_WakeupAlarm.apk

zipalign -v 4 /media/suyash/suyash_nas_1/AndroSandX_current/storage/analyses/1/apktool/dist/Gentle_WakeupAlarm.apk /media/suyash/suyash_nas_1/AndroSandX_current/storage/analyses/1/apktool/dist/Gentle_WakeupAlarm_aligned.apk

Decompilation and recompilation:
apktool_path,"d","-d",temp_ticket.file_path,"--output",str(extract_dir_name),"-f"
apktool_path,"b","-d",str(extract_dir_name)

'''








class layer_1_queue(object):
    pass


if __name__=="__main__":
    #layer_1_analysis()
    # temp_mdb = my_mdb()
    # temp_cuckoo_ticket = temp_mdb.cl_analysis.find_one({"target.file.sha256":"d3e7b0af0dbdd250cb9106580fc92c6e6800b398bf85f95428ae09e633625607"})
    # print(type(temp_cuckoo_ticket))
    # for x in temp_cuckoo_ticket:
    #
    #     print x, type(temp_cuckoo_ticket[x])
    #     raw_input()
    #     print x,"  :: ",temp_cuckoo_ticket[x]
    #     raw_input()

    #get_apktoo_info(None)
    #cmd_line(["/home/suyash/Desktop/Python_script/AndroSandX/apktool/apktool","d","/home/suyash/Desktop/APK_FOR_TEST/Gentle_WakeupAlarm.apk","--output","/home/suyash/Desktop/Python_script/AndroSandX/cuckoo/storage/analyses/1/apktool","-f"])
    #temp("/home/suyash/Desktop/Python_script/AndroSandX/cuckoo/storage/analyses/1/apktool")
    # ip_void_1 = []
    # ip_void_1.append(ipvoid("103.4.52.150"))
    # ip_void_1.append(ipvoid("156.97.56.64"))
    #get_network_conversations(2)

    #layer_1_init()
    #thread.start_new_thread(layer_1_new_ticket_watcher,())
    try:
        while True:
            layer_1_new_ticket_watcher()
            layer_1_init()
            layer_1_analysis()
            print(green("\n\n>>>>:: Layer 1 current queue ended looping again "))
            print(yellow("------Sleeping 600 sec------"))
            time.sleep(600)
    except:
        print(red(">>>>Layer 1 main excetion <<<<"))
        exit()
