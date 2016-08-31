from mongodb_ASX import my_mdb
from objects_ASX import global_var ,token ,ticket
import datetime

if __name__=='__main__':
    local_db = my_mdb()
    local_db.cl_new_tickets.drop()
    local_db.cl_incomplete_tokens.drop()
    local_db.cl_static_var.drop()

    tckt = ticket(None)
    tkn = token(None)
    gv = global_var()

    for x in range(1,20):
        tckt.ticket_id = x
        tckt.cuckoo_id = x
        tckt.file_path = str("filepath/%s"%x)
        tckt.hash_sha256 = "123131313131313"
        tckt.android_app_name = "Hello__ap_%s"%x
        tckt.android_package_name = None
        tckt.time_submission = datetime.datetime.utcnow()
        tckt.current_analysis_layer = divmod(x,4)[1]
        tckt.ai_feature = {'f1':'xx','f2':'zz','f3':'cc'}
        tckt.snort_signatures = {'sig1':'sid___1','sig2':'sid__2'}
        tckt.ai_decision = {'malware':20,'risk':40}
        tckt.report = {'<head>':'This is malware report','<body>':'malware report','<footer>':'Thank You'}
        tckt.analysis_end_time = (datetime.datetime.utcnow()+datetime.timedelta(hours=(divmod(x,4)[1])))
        tckt.analysis_status = 'incomplete'
        tckt.analysis_start_time = (datetime.datetime.utcnow())


        tkn.token_id = x
        tkn.ticket_id = x
        tkn.layer = divmod(x,4)[1]
        tkn.analysis_status = 'incomplete'
        tkn.genesis_time =  datetime.datetime.utcnow()



        gv.current_ticket_id +=1
        gv.current_token_id +=1
        #
        # print(tkn)
        # print(tckt)


        local_db.cl_new_tickets.insert(tckt.give_dict())
        local_db.cl_incomplete_tokens.insert(tkn.give_dict())

    local_db.cl_static_var.insert(gv.give_dict())

    print(gv)