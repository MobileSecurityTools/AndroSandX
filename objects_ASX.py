from collections import deque
from mongodb_ASX import my_mdb
from util.color import *
class ticket(object):
    def __init__(self,ticket_dict):
        # self.ticket_details = {
        #     "ticket_id" : None,
        #     "cuckoo_id":None,
        #     "file_path":None,
        #     "hash_sha256":None,
        #     "android_app_name":None,
        #     "android_package_name":None,
        #     "time_submission":None,
        #     "current_analysis_layer":None,
        #     "ai_feature":{},
        #     "snort_signatures":{},
        #     "ai_decision":{},
        #     "report":{},
        #     "analysis_end_time":None,
        #     "analysis_start_time":None,
        #     "analysis_status":'incomplete',
        #     "cuckoo_folder_id":None,
        #     "apktool_data_path":None
        # }
        if ticket_dict != None:
            self.ticket_id = ticket_dict['ticket_id']
            self.cuckoo_id = ticket_dict['cuckoo_id']
            self.cuckoo_folder_id = ticket_dict['cuckoo_folder_id']
            self.file_path = ticket_dict['file_path']
            self.hash_sha256 = ticket_dict['hash_sha256']
            self.android_app_name = ticket_dict['android_app_name']
            self.android_package_name = ticket_dict['android_package_name']
            self.time_submission = ticket_dict['time_submission']
            self.current_analysis_layer = ticket_dict['current_analysis_layer']
            self.ai_feature = ticket_dict['ai_feature']
            self.snort_signatures = ticket_dict['snort_signatures']
            self.ai_decision = ticket_dict['ai_decision']
            self.report = ticket_dict['report']
            self.analysis_end_time = ticket_dict['analysis_end_time']
            self.analysis_status = ticket_dict['analysis_status']
            self.analysis_start_time = ticket_dict['analysis_start_time']
            self.apktool_data_path = ticket_dict['apktool_data_path']

        else:
            self.ticket_id = None
            self.cuckoo_id = None
            self.cuckoo_folder_id = None
            self.file_path = None
            self.hash_sha256 = None
            self.android_app_name = None
            self.android_package_name = None
            self.time_submission = None
            self.current_analysis_layer = None
            self.ai_feature = None
            self.snort_signatures = None
            self.ai_decision = None
            self.report = None
            self.analysis_end_time = None
            self.analysis_status = None
            self.analysis_start_time = None
            self.apktool_data_path = None

    def __repr__(self):
        return repr({'ticket_id':self.ticket_id,
        'cuckoo_id':self.cuckoo_id,
        'cuckoo_folder_id':self.cuckoo_folder_id,
        'file_path':self.file_path,
        'hash_sha256':self.hash_sha256,
        'android_app_name':self.android_app_name,
        'android_package_name':self.android_package_name,
        'time_submission':self.time_submission,
        'current_analysis_layer':self.current_analysis_layer,
        'ai_feature':self.ai_feature,
        'snort_signatures':self.snort_signatures,
        'ai_decision':self.ai_decision,
        'report':self.report,
        'analysis_end_time':self.analysis_end_time,
        'analysis_status':self.analysis_status,
        'analysis_start_time':self.analysis_start_time,
        'apktool_data_path' : self.apktool_data_path})


    def give_dict(self):
        return dict({'ticket_id':self.ticket_id,
        'cuckoo_id':self.cuckoo_id,
        'cuckoo_folder_id':self.cuckoo_folder_id,
        'file_path':self.file_path,
        'hash_sha256':self.hash_sha256,
        'android_app_name':self.android_app_name,
        'android_package_name':self.android_package_name,
        'time_submission':self.time_submission,
        'current_analysis_layer':self.current_analysis_layer,
        'ai_feature':self.ai_feature,
        'snort_signatures':self.snort_signatures,
        'ai_decision':self.ai_decision,
        'report':self.report,
        'analysis_end_time':self.analysis_end_time,
        'analysis_status':self.analysis_status,
        'analysis_start_time':self.analysis_start_time,
        'apktool_data_path' : self.apktool_data_path})
    # def ticket_print(self):
    #     for key in self.ticket_details:
    #         print key," :".rjust(10),self.ticket_details[key]



class token(object):
    def __init__(self, token_dict):
        # self.token_details = {
        #     "token_id" : None,
        #     "ticket_id" : None,
        #     "layer" : None,
        #     "analysis_status":'incomplete'
        # }
        if token_dict != None:
            self.token_id =  token_dict['token_id']
            self.ticket_id = token_dict['ticket_id']
            self.layer = token_dict['layer']
            self.analysis_status = token_dict['analysis_status']
            self.genesis_time = token_dict['genesis_time']
        else:
            self.token_id =  None
            self.ticket_id = None
            self.layer = None
            self.analysis_status = None
            self.genesis_time = None
    def __repr__(self):
        return (repr({'token_id':self.token_id,'ticket_id':self.ticket_id,'analysis_status':self.analysis_status,'layer':self.layer,'genesis_time':self.genesis_time}))
    def give_dict(self):
        return dict({'token_id':self.token_id,'ticket_id':self.ticket_id,'analysis_status':self.analysis_status,'layer':self.layer,'genesis_time':self.genesis_time})

class global_var(object):
    _id = 1
    current_token_id = 0
    current_ticket_id = 0
    global_var_initialized = False
    global_token_queue  = deque()
    global_ticket_queue = deque()
    global_new_ticket_queue = deque()
    global_layer1_queue = deque()
    global_layer2_queue = deque()
    global_layer3_queue = deque()
    global_layer4_queue = deque()
    global_cuckoo_task_id = deque()



    def global_var_update(self):
        local_mdb = my_mdb()
        local_mdb.cl_static_var.save(self.give_dict())
        print green("GLobal Var Save to MongoDB")



    def __init__(self):
        pass
    def __repr__(self):
        return repr({'_id':self._id,'current_token_id':self.current_token_id,'current_ticket_id':self.current_ticket_id})
    def give_dict(self):
        return dict({'_id':self._id,'current_token_id':self.current_token_id,'current_ticket_id':self.current_ticket_id})

if __name__=="__main__":
    pass