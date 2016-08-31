from util.color import *
from subprocess import call as cmd_line, check_output
from os import path
import re
import objects_ASX
import mongodb_ASX
import os

def get_apktool_info(temp_ticket):
    print yellow("Attempting to perform apktool based decomilation >> Ticket_ID : %s"%(temp_ticket.ticket_id))
    androSandx_path = path.split(path.abspath(__file__))[0]


    tool_folder_path = path.join(androSandx_path,"0_Tools")
    analysis_folder_path = path.join(androSandx_path,"cuckoo","storage","analyses",str(temp_ticket.cuckoo_folder_id))

    # apktool_path = path.join(androSandx_path, "apktool", "apktool")


    apktool_path = path.join(tool_folder_path, "apktool")
    dex2jar_path = path.join(tool_folder_path,"dex2jar-2.0", "d2j-dex2jar.sh")
    zipalign_path = path.join(tool_folder_path,"24.0.0","zipalign")

    binary_path = path.join(analysis_folder_path,"binary")

    dex2jar_output = path.join(analysis_folder_path, "dex2jar_output")
    try:
        os.mkdir(dex2jar_output, 0755)
    except OSError:
        pass

    apktool_output_folder = path.join(androSandx_path, "cuckoo", "storage", "analyses", str(temp_ticket.cuckoo_folder_id),
                                 "apktool_output")
    #apktool_output_folder = path.join(androSandx_path,"cuckoo","storage","analyses","12","apktool")

    #print "apktool_output_folder",apktool_output_folder
    #print("command :"+apktool_path+" "+"d"+" "+temp_ticket.file_path+" "+"--output"+" "+apktool_output_folder+"-f")


    # Decompilation and recompilation:
    # apktool_path, "d", "-d", temp_ticket.file_path, "--output", str(apktool_output_folder), "-f"
    # apktool_path, "b", "-d", str(apktool_output_folder)

    #dex2jar

    cmd_line([dex2jar_path, binary_path, "-o",dex2jar_output,"--force"])

    #apktool decompile and recompile in debug mode
    cmd_line([apktool_path,"d","-d",binary_path,"--output",apktool_output_folder,"-f"])
    cmd_line([apktool_path,"b","-d",apktool_output_folder,"-f"])
    #------------------

    resigned_apk_path = path.join(apktool_output_folder,"dist","binary")
    #signing of the application
    # create certificate
    # #--- required only when creating new self signed cert
    # cmd_line(
    #     ["keytool", "-genkey", "-v", "-keystore", "suyash_key_store.keystore", "-alias", "suyash_key_Jul2_2016", "-keyalg", "RSA",
    #      "-keysize", "2048", "-validity", "90"])
    # #------

    #sign the jar
    cmd_line(["jarsigner", "-verbose", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1", "-keystore",
              "suyash_key_store.keystore", resigned_apk_path, "suyash_key_Jul2_2016"])


    #verify the jar
    cmd_line(["jarsigner", "-verify", "-verbose", "-certs" , resigned_apk_path])

    #zipalign the apk
    resigned_zipalign_pk_path = path.join(apktool_output_folder,"dist","binary__signed_zipalign")

    cmd_line([zipalign_path, "-v","-f", "4", resigned_apk_path, resigned_zipalign_pk_path])

    #------------------

    print green("Successfully Decompiled and recompiled and signed in debugging mode \nDir path :: %s\nDex2Jar path :: %s\nSigned apk path :: %s"%(apktool_output_folder,dex2jar_output,resigned_zipalign_pk_path))
    app_name = get_app_name(apktool_output_folder)
    mongodb_ASX.my_mdb().cl_analysis_tickets.update({"ticket_id":ticket.ticket_id},{"$set":{"android_app_name":app_name}})


    ## Tranfer the complete file to NAS storage for further use.

    '''
    Signing of application:
    keytool -genkey -v -keystore suyash_key_store.keystore -alias suyash_key -keyalg RSA -keysize 2048 -validity 10

    jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore suyash_key_store.keystore /media/suyash/suyash_nas_1/AndroSandX_current/storage/analyses/1/apktool/dist/Gentle_WakeupAlarm.apk suyash_key

    jarsigner -verify -verbose -certs /media/suyash/suyash_nas_1/AndroSandX_current/storage/analyses/1/apktool/dist/Gentle_WakeupAlarm.apk

    zipalign -v 4 /media/suyash/suyash_nas_1/AndroSandX_current/storage/analyses/1/apktool/dist/Gentle_WakeupAlarm.apk /media/suyash/suyash_nas_1/AndroSandX_current/storage/analyses/1/apktool/dist/Gentle_WakeupAlarm_aligned.apk

    Decompilation and recompilation:
    apktool_path,"d","-d",temp_ticket.file_path,"--output",str(apktool_output_folder),"-f"
    apktool_path,"b","-d",str(apktool_output_folder)

    #Get a java code and open
    d2j-dex2jar.sh

    '''

    #print "temp_ticket.file_path :",temp_ticket.file_path
    # Decode apk in debug mode: $ apktool d -d -o out app.apk
    # Build new apk in debug mode: $ apktool b -d out

    #return apktool_output_folder

def get_app_name(apktool_output_folder):
    print yellow("Attempting to extract actual app name >> ")
    try:
        manifest_file = open(path.join(apktool_output_folder,'AndroidManifest.xml'),"r")
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
            #print path.join(apktool_output_folder,"res","values",file_1)
            file_contining_name = open(path.join(apktool_output_folder,"res","values",file_1),"r")
            temp_string = file_contining_name.read()
            search_string  = ""
            app_name = re.search(r"\"%s\">.*?<"%(string_2),temp_string).group(0)
            app_name = app_name.split(">")[1]
            app_name = app_name.replace("<","")
            #<string name="app_name">Gentle Wakeup</string>

            #print "Temp String: ",temp_string
            # print "file_1: ",file_1
            # print "string_2: ",string_2
            print magenta("app_name: %s"%(app_name))
        return app_name
    except:
        print "NOT_ABLE_TO_FIND_APP_NAME"
        return "NOT_ABLE_TO_FIND_APP_NAME"

    #get name - regex "<application(.*)?android:label=("(.*)?"|'(.*)?')"

if __name__ == "__main__":
    ticket_id = int(raw_input("Please enter the Ticket_id :: "))
    temp_mdb = mongodb_ASX.my_mdb()
    ticket = objects_ASX.ticket(temp_mdb.cl_analysis_tickets.find_one({"ticket_id":ticket_id}))
    get_apktool_info(ticket)
    print "Ticket Details:"
    print "Ticket_id : %s"%ticket.ticket_id
    print "Folder ID: %s"%ticket.cuckoo_folder_id
    print "Hash: %s"%ticket.hash_sha256
