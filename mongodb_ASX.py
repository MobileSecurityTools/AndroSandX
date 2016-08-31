import pymongo as mdb
import sys

import traceback
from util.color import s_violet,s_red,yellow,green
import objects_ASX



class my_mdb():
    def __init__(self):
        try:
            self.db_asx_conn = mdb.MongoClient('192.168.0.105',27017)

            self.db_asx_analysis_core = self.db_asx_conn.analysis_core_db
            self.db_asx_core = self.db_asx_conn.asx_core


            self.cl_analysis = self.db_asx_analysis_core.analysis # this is cuckoo db

            self.cl_analysis_tickets = self.db_asx_core.analysis_tickets
            self.cl_new_tickets = self.db_asx_core.new_tickets
            self.cl_error_log = self.db_asx_core.error_log
            self.cl_static_var = self.db_asx_core.static_var
            self.cl_analyzed_url_ip = self.db_asx_core.analyzed_url_ip
            self.cl_vt_ipv_results = self.db_asx_core.vt_ipv_results
            self.cl_pcap_snort_log = self.db_asx_core.pcap_snort_log

        except:
            print "Error connecting to data base    "

    def close(self):
        self.db_asx_conn.close()
    def drop_all(self):
        print s_red(" !!! Warining !!! >> Droping all databases hit enter to continue")
        raw_input()
        #self.cl_analysis.drop()
        self.cl_analysis_tickets.drop()
        self.cl_new_tickets.drop()
        self.cl_error_log.drop()
        self.cl_static_var.drop()
        self.cl_vt_ipv_results.drop()
        self.cl_pcap_snort_log.drop()
        gv = objects_ASX.global_var()
        self.cl_static_var.insert(gv.give_dict())

        print (self.cl_static_var.find_one())

    def create_all(self):
        print green(" Creating all required collections used asx_core")
        #-- creatign all collections

        try:
            self.db_asx_core.create_collection("analysis_tickets")
        except:
            pass

        try:
            self.db_asx_core.create_collection("new_tickets")
        except: pass

        try:
            self.db_asx_core.create_collection("static_var")
        except:pass

        try:
            self.db_asx_core.create_collection("analyzed_url_ip")
        except:pass

        try:
            self.db_asx_core.create_collection("vt_ipv_results")
        except:
            pass

        try:
           self.db_asx_core.create_collection("pcap_snort_log")
        except:
            pass
        #-- end of creation of collections


#new req ->new_ticket, incomplete_token then pass to layer on and transfer ticket from new to analysis_ticket,



# create this db
# have collections as
#   1.global_completed_tickets , global_incomplete_tickets
#   2.global_new
#   3.layer2_queued
#   4.layer3_queued
#   5.layer4_a_queued
#   6.layer4_b_queued
#   7.layer5_queued
#   8.layer6_queued
#   9.layer7_queued
#   10.global_manual_queued
#   11.global_manual_completed


#Database : asx_core
#Collections created:
# global_analysis_tickets
# global_complete_tokens
# global_incomplete_tokens
# global_new_tickets


# Cuckoo DB: analysis_core_db
#     Collections:
#         analysis
#         cuckoo_schema
#         fs.chunks
#         fs.files
#         system.indexes


# Ticket DB:asx_core
#     Collections:
#         global_analysis_tickets
#         global_complete_tokens
#           -token_id
#           -ticket_id
#           -layer
#           -time_stamps {"submission":None,"layer_1":None,...}
#         global_incomplete_tokens
#         global_new_tickets
#         global_error_log
#           -time
#           -module
#           -function
#           -error
#         system.indexes
#         global_static_var
#           -current_token_id
#           -current_ticket_id
#         analyzed_url_ip
#           -resource
#           -result
#           -hash




if __name__=="__main__":
     mdb_1 = my_mdb()
     mdb_1.drop_all()
     mdb_1.create_all()
    # if (raw_input("Do you want to clear the datebase :: Confirm my pressing \"Y\"") in ("y","Y")):
    #     try:
    #         temp_global_var = global_var()
    #         temp_global_var.global_var_details["current_token_id"] = 0
    #         temp_global_var.global_var_details["current_ticket_id"] = 0
    #         print "Inserting Doc: ",temp_global_var.global_var_details
    #         db_success =  mdb_1.cl_static_var.drop()
    #         print "Droping previous database"
    #         db_success = mdb_1.cl_static_var.insert(temp_global_var.global_var_details)
    #         if db_success:
    #             print "Successfully cleared the data base and reinitiated"
    #     except:
    #         print "Error!!"
    #         err = sys.exc_info()
    #         traceback.print_exception(*err)
    # else:
    #    print "Thank you NO changes are made to database"
    #print "Use Dummy data creator for now// later create a drop function"