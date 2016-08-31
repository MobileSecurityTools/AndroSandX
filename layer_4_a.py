import objects_ASX
from mongodb_ASX import my_mdb
import re
from layer_2 import virustotal
import time
import traceback
from   util.color import *
import hashlib

class ai_features(object):
    def __init__(self, ticket):
        self.mdb = my_mdb()

        self.ticket = ticket
        self.analysis_data = self.mdb.cl_analysis.find_one({"target.file.sha256":ticket.hash_sha256})
        self.snort_data = self.mdb.cl_pcap_snort_log.find_one({"hash_sha256":ticket.hash_sha256})
        self.vt_ip_result = self.mdb.cl_vt_ipv_results.find_one({"file_hash_sha256":ticket.hash_sha256})

        try:
            droidmon_exists = 0
            if len(self.analysis_data["droidmon"]) != 0:
                droidmon_exists = 1
                print green("Droidmon exists fro ticket_id: %s"%(self.ticket.ticket_id))
            self.mdb.cl_analysis_tickets.update({"hash_sha256":ticket.hash_sha256},{"$set":{"droidmon_exists":droidmon_exists}})
        except KeyError:
            pass
        except:
            traceback.print_exc()
            self.mdb.cl_analysis_tickets.update({"hash_sha256": ticket.hash_sha256},{"$set": {"droidmon_exists": 0}})


        self.feature_dict = {
            'know_adware': 0,
            'dangerous_permissions': 0,
            'dynamic_code': 0,
            'known_malware_sig_string': 0,
            'use_of_native_code': 0,
            'hiden_payload': 0,
            'use_of_android_packer': 0,
            'use_of_reflection_code': 0,
            'aborted_broadcast': 0,
            'contains_another_apk': 0,
            'contains_arm_binary': 0,
            'contains_dex': 0,
            'contains_jar': 0,
            'contains_so': 0,
            'device_admin_granted': 0,
            'execution_of_shell_command': 0,
            'device_fingerprinting': 0,
            'installed_new_application': 0,
            'queried_account_info': 0,
            'queried_installed_apps': 0,
            'accessed_private_information': 0,
            'audio_recording': 0,
            'registered_new_receiver_at_runtime': 0,
            'sent_sms': 0,
            'stoped_processes': 0,
            'uses_location': 0,
            'using_camera': 0,
            'creates_exe': 0,
            'use_of_ICMP_request': 0,
            'use_of_IRC': 0,
            'use_of_SMTP': 0,
            #-----------------------
            'cryptography_used': 0,
            'crypto_algo_DES': 0,
            'crypto_algo_AES': 0,
            'crypto_algo_RC4': 0,
            'Use_of_Shared_preference': 0,
            'Shared_preference_contain_URL': 0,
            'shared_preference_URL_flaged_by_virustotal': 0,
            'apk_accessed_from_storage': 0,
            'zip_accessed_from_storage': 0,
            'jar_accessed_from_storage': 0,
                # 'queried_private_information': 0,
            'accessed_so_file': 0,
                # 'queried_for_installed_application': 0,
            'shared_preference_contains_URL_to_apk_file': 0,

            # permisssion
            'internet_permission': 0,
            'write_external_storage': 0,
            'change_wifi_state': 0,
            'access_fine_location': 0,
            'access_coarse_location': 0,
                # 'system_alert_window': 0,
            'wake_lock': 0,
            'read_history_bookmark': 0,
            'write_history_bookmark': 0,
            'read_phone_state': 0,
                # 'get_tasks': 0,
            'access_camera': 0,
            'read_external_storage': 0,
            'read_logs': 0,
            'read_calendar': 0,
            'write_calendar': 0,
                # 'install_shortcut': 0,
            'mount_unmount_filesystem': 0,
            'install_uninstall_shortcut': 0,
            'download_without_notification': 0,
            'modify_secure_system_setting': 0,
            'directly_install_application': 0,
            'modify_phone_state': 0,
            'write_accesspoint_proxy_setting': 0,
            'turn_phone_on_off': 0,
            'create_bluetooth_connection': 0,
            'intercept_outgoing_call': 0,
            'directly_call_phone_numbers': 0,
            'access_superuser': 0,
            'kill_background_process': 0,
            'read_contact': 0,
            'receive_WAP_push_message': 0,
            'get_account': 0,
            'manage_account_and_passwords': 0,
            'disable_key_lock': 0,
            'access_download_manager': 0,
            'control_vibrator': 0,
            'sms_send_permission': 0,
            'restart_packages': 0,
            'write_sms_mms': 0,
            'read_sms_mms': 0,
            'receive_sms': 0,
            'change_network_state': 0,
            'interact_accross_user_full': 0,
            'broadcast_sticky': 0,
            'write_setting': 0,
            'get_running_task': 0,
            'system_level_alert': 0,
            'receive_boot_completed': 0,


            # Finger printing
            'MAC_address': 0,
            'Network_Operator': 0,
            'Device_ID': 0,
            'Sim_serial_Number': 0,
            'Sim_Operator_Name': 0,
            'get_network_country': 0,
            'sim_iso_country': 0,
            'get_line_number': 0,

            # Broadcast receiver
            'screen_On': 0,
            'screen_off': 0,
            'package_added': 0,
            'package_removed': 0,
            'SMS_received': 0,
            'SMS_delivered': 0,
            'device_admin_enabled': 0,
            'boot_completed': 0,
            'action_power_connected': 0,
            'action_power_disconnected': 0,
            'battery': 0,
            'user_present': 0,
            'media_changes': 0,
            'head_set_detect': 0,
            'proxy_change': 0,
            'connectivity_change': 0,
            'baidu_silent_install': 0,
            'baidu_detect_root': 0,

            # Static Method/function calls
            'cypto_function': 0,
            'contact_read': 0,
            'camera': 0,
            'bookmark': 0,
            'location': 0,
            'send_sms': 0,

            # some logics which indicates suspecious behaviour
            'location_wallpaper_readlogs': 0,
            'credential_killProcess_audioRecord_camera_location_internet': 0,

            # Network forensics
            'IP_address_blacklisted': 0,
            'IP_address_belongs_high_severity_country': 0,
            'IP_address_hosting_flaged_url_on_Virustotal': 0,
            'IP_address_hosting_malicous_files_on_Virustotal': 0,
                # 'DNS_request_for_domain_flaged_by_Virustotal': 0,
            'URL_flaged_on_virustotal': 0,
            'ethernet_frames': 0,
            'ethernet_bytes': 0,
            'arp_frames': 0,
            'arp_bytes': 0,
            'ip_frames': 0,
            'ip_bytes': 0,
            'udp_frames': 0,
            'udp_bytes': 0,
            'tcp_frames': 0,
            'tcp_bytes': 0,
            'dns_frames': 0,
            'dns_bytes': 0,
            'irc_frames': 0,
            'irc_bytes': 0,
            'smtp_frames': 0,
            'smtp_bytes': 0,
            'udp_uploaded_data': 0,
            'udp_downloaded_data': 0,
            'tcp_uploaded_data': 0,
            'tcp_downloaded_data': 0,
            'udp_coversation_average_data_transfer_rate': 0,
            'tcp_coversation_average_data_transfer_rate': 0,
            'snort_alert_for_malaware_related_activity': 0,
            'snort_alert_for_exploit_kit_activity': 0,
            'snort_high_severity_alert': 0,

        }

        self.execute_all_AI_feature_collection_functions()


    def execute_all_AI_feature_collection_functions(self):
        self.know_adware()
        self.dangerous_permissions()
        self.dynamic_code()
        self.known_malware_sig_string()
        self.use_of_native_code()
        self.hiden_payload()
        self.use_of_android_packer()
        self.use_of_reflection_code()
        self.aborted_broadcast()
        self.contains_another_apk()
        self.contains_arm_binary()
        self.contains_dex()
        self.contains_jar()
        self.contains_so()
        self.device_admin_granted()
        self.execution_of_shell_command()
        self.device_fingerprinting()
        self.installed_new_application()
        self.queried_account_info()
        self.queried_installed_apps()
        self.accessed_private_information()
        self.audio_recording()
        self.registered_new_receiver_at_runtime()
        self.sent_sms()
        self.stoped_processes()
        self.uses_location()
        self.using_camera()
        self.creates_exe()
        self.use_of_ICMP_request()
        self.use_of_IRC()
        self.use_of_SMTP()
        # -----------------------
        self.cryptography_used()
        self.crypto_algo_DES()
        self.crypto_algo_AES()
        self.crypto_algo_RC4()
        self.Use_of_Shared_preference()
        self.Shared_preference_contain_URL()
        self.shared_preference_URL_flaged_by_virustotal()
        self.apk_accessed_from_storage()
        self.zip_accessed_from_storage()
        self.jar_accessed_from_storage()
        # 'queried_private_information': 0,
        self.accessed_so_file()
        # 'queried_for_installed_application': 0,
        self.shared_preference_contains_URL_to_apk_file()

        # permisssion
        self.internet_permission()
        self.write_external_storage()
        self.change_wifi_state()
        self.access_fine_location()
        self.access_coarse_location()
        # 'system_alert_window': 0,
        self.wake_lock()
        self.read_history_bookmark()
        self.write_history_bookmark()
        self.read_phone_state()
        # 'get_tasks': 0,
        self.access_camera()
        self.read_external_storage()
        self.read_logs()
        self.read_calendar()
        self.write_calendar()
        # 'install_shortcut': 0,
        self.mount_unmount_filesystem()
        self.install_uninstall_shortcut()
        self.download_without_notification()
        self.modify_secure_system_setting()
        self.directly_install_application()
        self.modify_phone_state()
        self.write_accesspoint_proxy_setting()
        self.turn_phone_on_off()
        self.create_bluetooth_connection()
        self.intercept_outgoing_call()
        self.directly_call_phone_numbers()
        self.access_superuser()
        self.kill_background_process()
        self.read_contact()
        self.receive_WAP_push_message()
        self.get_account()
        self.manage_account_and_passwords()
        self.disable_key_lock()
        self.access_download_manager()
        self.control_vibrator()
        self.sms_send_permission()
        self.restart_packages()
        self.write_sms_mms()
        self.read_sms_mms()
        self.receive_sms()
        self.change_network_state()
        self.interact_accross_user_full()
        self.broadcast_sticky()
        self.write_setting()
        self.get_running_task()
        self.system_level_alert()
        self.receive_boot_completed()

        # Finger printing
        self.MAC_address()
        self.Network_Operator()
        self.Device_ID()
        self.Sim_serial_Number()
        self.Sim_Operator_Name()
        self.get_network_country()
        self.sim_iso_country()
        self.get_line_number()

        # Broadcast receiver
        self.screen_On()
        self.screen_off()
        self.package_added()
        self.package_removed()
        self.SMS_received()
        self.SMS_delivered()
        # self.device_admin_enabled()
        self.boot_completed()
        self.action_power_connected()
        self.action_power_disconnected()
        self.battery()
        self.user_present()
        self.media_changes()
        self.head_set_detect()
        self.proxy_change()
        self.connectivity_change()
        self.baidu_silent_install()
        self.baidu_detect_root()

        # Static Method/function calls
        self.cypto_function()
        self.contact_read()
        self.camera()
        self.bookmark()
        self.location()
        self.send_sms()

        # some logics which indicates suspecious behaviour
        self.location_wallpaper_readlogs()
        self.credential_killProcess_audioRecord_camera_location_internet()

        # Network forensics
        self.IP_address_blacklisted()
        self.IP_address_belongs_high_severity_country()
        self.IP_address_hosting_flaged_url_on_Virustotal()
        self.IP_address_hosting_malicous_files_on_Virustotal()
        # 'DNS_request_for_domain_flaged_by_Virustotal': 0,
        self.URL_flaged_on_virustotal()
        self.ethernet_frames()
        self.ethernet_bytes()
        self.arp_frames()
        self.arp_bytes()
        self.ip_frames()
        self.ip_bytes()
        self.udp_frames()
        self.udp_bytes()
        self.tcp_frames()
        self.tcp_bytes()
        self.dns_frames()
        self.dns_bytes()
        self.irc_frames()
        self.irc_bytes()
        self.smtp_frames()
        self.smtp_bytes()
        self.udp_uploaded_data()
        self.udp_downloaded_data()
        self.tcp_uploaded_data()
        self.tcp_downloaded_data()
        self.udp_coversation_average_data_transfer_rate()
        self.tcp_coversation_average_data_transfer_rate()
        self.snort_alert_for_malaware_related_activity()
        self.snort_alert_for_exploit_kit_activity()
        self.snort_high_severity_alert()

        self.mdb.cl_analysis_tickets.update({"hash_sha256":self.ticket.hash_sha256},{"$set":{"ai_feature":self.feature_dict,"current_analysis_layer":"layer_4_a"}})
        print yellow("Updated/stored the features for ticket_id: %s"%(self.ticket.ticket_id))

    # behavioural
    def know_adware(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('android_AirPush_Adware','android_Umeng_Adware'):
                self.feature_dict['know_adware'] = 1
        pass

    def dangerous_permissions(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('android_dangerous_permissions',):
                self.feature_dict['dangerous_permissions'] = 1
        pass

    def dynamic_code(self):
        # Static apkinfo detection
        for each in self.analysis_data['signatures']:
            if each['name'] in ('android_dynamic_code',):
                self.feature_dict['dynamic_code'] = 1
        pass


    def known_malware_sig_string(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('android_malware_sandrorat', 'android_maware_androrat', 'android_maware_iBanking'):
                self.feature_dict['known_malware_sig_string'] = 1
        pass

    def use_of_native_code(self):
        # Static apkinfo detection
        for each in self.analysis_data['signatures']:
            if each['name'] in ('android_native_code',):
                self.feature_dict['use_of_native_code'] = 1
        pass

    def hiden_payload(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('android_hidden_payload',):
                self.feature_dict['hiden_payload'] = 1
        pass

    def use_of_android_packer(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('android_packer',):
                self.feature_dict['use_of_android_packer'] = 1
        pass

    def use_of_reflection_code(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('android_reflection_code',):
                self.feature_dict['use_of_reflection_code'] = 1
        pass

    def aborted_broadcast(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_aborted_broadcast_receiver',):
                self.feature_dict['aborted_broadcast'] = 1
        pass

    def contains_another_apk(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_contains_apk',):
                self.feature_dict['contains_another_apk'] = 1
        pass

    def contains_arm_binary(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_contains_arm_binary',):
                self.feature_dict['contains_arm_binary'] = 1
        pass

    def contains_dex(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_contains_dex',):
                self.feature_dict['contains_dex'] = 1
        pass

    def contains_jar(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_contains_jar',):
                self.feature_dict['contains_jar'] = 1
        pass

    def contains_so(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_contains_so',):
                self.feature_dict['contains_so'] = 1
        pass

    def device_admin_granted(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_device_admin',):
                self.feature_dict['device_admin_granted'] = 1
        pass

    def execution_of_shell_command(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_executed_shell_command',):
                self.feature_dict['execution_of_shell_command'] = 1
        pass

    def device_fingerprinting(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_fingerprint',):
                self.feature_dict['device_fingerprinting'] = 1
        pass

    def installed_new_application(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_installed_app',):
                self.feature_dict['installed_new_application'] = 1
        pass

    def queried_account_info(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_queried_account_info',):
                self.feature_dict['queried_account_info'] = 1
        pass
    11
    def queried_installed_apps(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_queried_installed_apps',):
                self.feature_dict['queried_installed_apps'] = 1
        pass



    def accessed_private_information(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_queried_private_information',):
                self.feature_dict['accessed_private_information'] = 1
        pass


    def audio_recording(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_recording_audio',):
                self.feature_dict['audio_recording'] = 1
        pass

    def registered_new_receiver_at_runtime(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_registered_receiver_runtime',):
                self.feature_dict['registered_new_receiver_at_runtime'] = 1
        pass

    def sent_sms(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_sent_sms_messages'):
                self.feature_dict['sent_sms'] = 1
        pass

    def stoped_processes(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_stopped_processes',):
                self.feature_dict['stoped_processes'] = 1
        pass

    def uses_location(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_uses_location',):
                self.feature_dict['uses_location'] = 1
        pass

    def using_camera(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('application_using_the_camera',):
                self.feature_dict['using_camera'] = 1
        pass

    def creates_exe(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('creates_exe',):
                self.feature_dict['creates_exe'] = 1
        pass

    def use_of_ICMP_request(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('network_icmp',):
                self.feature_dict['use_of_ICMP_request'] = 1
        pass

    def use_of_IRC(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('network_irc',):
                self.feature_dict['use_of_IRC'] = 1
        pass

    def use_of_SMTP(self):
        for each in self.analysis_data['signatures']:
            if each['name'] in ('network_smtp',):
                self.feature_dict['use_of_SMTP'] = 1
        pass

#----------------------------------------------------
    def cryptography_used(self):
        try:
            if len(self.analysis_data['apkinfo']['static_method_calls']['crypto_method_calls']) != 0:
                self.feature_dict['cryptography_used'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def crypto_algo_DES(self):
        try:
            for each in self.analysis_data['droidmon']['crypto_keys']:
                if each['type'] == 'DES':
                   self.feature_dict['crypto_algo_DES'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def crypto_algo_AES(self):
        try:
            for each in self.analysis_data['droidmon']['crypto_keys']:
                if each['type'] == 'AES':
                    self.feature_dict['crypto_algo_AES'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def crypto_algo_RC4(self):
        try:
            for each in self.analysis_data['droidmon']['crypto_keys']:
                if each['type'] == 'RC4':
                    self.feature_dict['crypto_algo_RC4'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def Use_of_Shared_preference(self):
        try:
            if len(self.analysis_data['droidmon']['SharedPreferences']) != 0:
                self.feature_dict['Use_of_Shared_preference'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def Shared_preference_contain_URL(self):
        try:
            for each in self.analysis_data['droidmon']['SharedPreferences']:
                if re.match(r"http[s]?:\/\/[^\s]*\.[a-zA-Z]{2,3}\/[^\s]*",each['value']):
                    self.feature_dict['Shared_preference_contain_URL'] = 1

        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def shared_preference_URL_flaged_by_virustotal(self):
        try:
            if self.feature_dict['Shared_preference_contain_URL'] == 1:
                list_of_urls = []
                for each in self.analysis_data['droidmon']['SharedPreferences']:
                    # list_of_urls.extend(re.findall(r"http[s]?:\/\/[^\s]*\.[a-zA-Z]{2,3}\/[^\s]*", each['value']))

                    list_of_urls.extend(re.findall(r"http[s]?:\/\/[^\s\",\]\[]*\.[a-zA-Z]{2,3}\/[^\s\",\[\]]*", each['value']))
                    list_of_urls.extend(re.findall(r"(http[s]?:\/\/[^\s\",\]\[]*\.[a-zA-Z]{2,3}$)", each['value']))
                    list_of_urls.extend(re.findall(r"(http[s]?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/?[^\s\";,\]\[]*)", each['value']))

                if len(list_of_urls)!=0:
                    for each in list_of_urls:
                        each = each.encode(encoding='utf-8',errors='ignore')
                        # in pass 1 - submitting result
                        #--- pass1 from here
                        # if self.mdb.cl_analyzed_url_ip.find_one({"hash": hashlib.sha256(each).hexdigest()}) == None
                            # print red("Sending URL for VT scan: URL: %s"%(each))
                            # virustotal('url_scan', each)
                            # time.sleep(5) # just for rading and waiting for results
                        # else:
                        #     print (green("URL already analyzed :: %s"%(each)))
                        # #--- pass 1 till here
                        #result = virustotal('url_scan',each).result

                        #pass 2 - fetching result
                        # passs2 from here---
                        result = self.mdb.cl_analyzed_url_ip.find_one({"hash": hashlib.sha256(each).hexdigest()})
                        if result == None:
                            print red("Sending URL for VT report: URL: %s" % (each))
                            result = virustotal('url_report',each).result
                            time.sleep(20)
                            # if result['verbose_msg'] in ('The requested resource is not among the finished, queued or pending scans','Resource does not exist in the dataset'):
                            if result['response_code'] in (0,'0'):
                                print red("Sending URL for VT scan: URL: %s" % (each))
                                virustotal('url_scan', each)
                                time.sleep(30)
                                result = virustotal('url_report', each).result
                                # if result['verbose_msg']  in ('The requested resource is not among the finished, queued or pending scans','Resource does not exist in the dataset'):
                                if result['response_code'] in (0,'0'):
                                    time.sleep(40)
                                    result = virustotal('url_report', each).result
                            print green("VT Results :: %s" % (result))
                            if(result["response_code"]!=0):
                                self.mdb.cl_analyzed_url_ip.insert({"hash": hashlib.sha256(each).hexdigest(), "result": result})
                                print yellow("Result added to analyzed_url_ip collection")
                            else:
                                print(red("Error in Fetching result for URL %s"%(each)))
                        else:
                            print(green("Result already present for URL: %s\n %s"%(each,result)))
                        try:
                            if result['positives'] > 0:
                                self.feature_dict['shared_preference_URL_flaged_by_virustotal'] = 1
                                return
                            #--- pass2 till here
                        except KeyError:
                            pass







        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def apk_accessed_from_storage(self):
        try:
            for each in self.analysis_data['droidmon']['file_accessed']:
                if re.match(r".*\.(apk|APK).*", each):
                    self.feature_dict['apk_accessed_from_storage'] = 1

        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def zip_accessed_from_storage(self):
        try:
            for each in self.analysis_data['droidmon']['file_accessed']:
                if re.match(r".*\.(zip|ZIP).*", each):
                    self.feature_dict['zip_accessed_from_storage'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def jar_accessed_from_storage(self):
        try:
            for each in self.analysis_data['droidmon']['file_accessed']:
                if re.match(r".*\.(jar|JAR).*", each):
                    self.feature_dict['jar_accessed_from_storage'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    # def queried_private_information(self):
    #     pass

    def accessed_so_file(self):
        try:
            for each in self.analysis_data['droidmon']['file_accessed']:
                if re.match(r".*\.(so|SO).*", each):
                    self.feature_dict['accessed_so_file'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass


    # def queried_for_installed_application(self):
    #     pass

    def shared_preference_contains_URL_to_apk_file(self):
        try:
            for each in self.analysis_data['droidmon']['SharedPreferences']:
                if re.match(r"http[s]?:\/\/[^\s]*\.[a-zA-Z]{2,3}\/[^\s]*\.apk[^\sa-zA-z]*", each['value']):
                    self.feature_dict['shared_preference_contains_URL_to_apk_file'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    # permisssion
    def internet_permission(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.INTERNET',):
                    self.feature_dict['internet_permission'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def write_external_storage(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.WRITE_EXTERNAL_STORAGE',):
                    self.feature_dict['write_external_storage'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def change_wifi_state(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.CHANGE_WIFI_STATE',):
                    self.feature_dict['change_wifi_state'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def access_fine_location(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.ACCESS_FINE_LOCATION',):
                    self.feature_dict['access_fine_location'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass


    def access_coarse_location(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.ACCESS_COARSE_LOCATION',):
                    self.feature_dict['access_coarse_location'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass


    def mount_unmount_filesystem(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.MOUNT_UNMOUNT_FILESYSTEMS',):
                    self.feature_dict['mount_unmount_filesystem'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def install_uninstall_shortcut(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'].find('UNINSTALL_SHORTCUT')!= -1 or each['name'].find('INSTALL_SHORTCUT')!= -1:
                    self.feature_dict['install_uninstall_shortcut'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def download_without_notification(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.DOWNLOAD_WITHOUT_NOTIFICATION',):
                    self.feature_dict['download_without_notification'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def modify_secure_system_setting(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.WRITE_SECURE_SETTINGS',):
                    self.feature_dict['modify_secure_system_setting'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def directly_install_application(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.INSTALL_PACKAGES',):
                    self.feature_dict['directly_install_application'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def modify_phone_state(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.MODIFY_PHONE_STATE',):
                    self.feature_dict['modify_phone_state'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def write_accesspoint_proxy_setting(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.WRITE_APN_SETTINGS',):
                    self.feature_dict['write_accesspoint_proxy_setting'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def turn_phone_on_off(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.DEVICE_POWER',):
                    self.feature_dict['turn_phone_on_off'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def create_bluetooth_connection(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.BLUETOOTH',):
                    self.feature_dict['create_bluetooth_connection'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def intercept_outgoing_call(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.PROCESS_OUTGOING_CALLS',):
                    self.feature_dict['intercept_outgoing_call'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def directly_call_phone_numbers(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.CALL_PHONE',):
                    self.feature_dict['directly_call_phone_numbers'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def access_superuser(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.ACCESS_SUPERUSER',):
                    self.feature_dict['access_superuser'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def kill_background_process(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.KILL_BACKGROUND_PROCESSES',):
                    self.feature_dict['kill_background_process'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def read_contact(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.READ_CONTACTS',):
                    self.feature_dict['read_contact'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def receive_WAP_push_message(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.RECEIVE_WAP_PUSH',):
                    self.feature_dict['receive_WAP_push_message'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def get_account(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.GET_ACCOUNTS',):
                    self.feature_dict['get_account'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def manage_account_and_passwords(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.MANAGE_ACCOUNTS',):
                    self.feature_dict['manage_account_and_passwords'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def disable_key_lock(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.DISABLE_KEYGUARD',):
                    self.feature_dict['disable_key_lock'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def access_download_manager(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.ACCESS_DOWNLOAD_MANAGER',):
                    self.feature_dict['access_download_manager'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def control_vibrator(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.VIBRATE',):
                    self.feature_dict['control_vibrator'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def sms_send_permission(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.SEND_SMS',):
                    self.feature_dict['sms_send_permission'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def restart_packages(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.RESTART_PACKAGES',):
                    self.feature_dict['restart_packages'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def write_sms_mms(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.WRITE_SMS',):
                    self.feature_dict['write_sms_mms'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def read_sms_mms(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.READ_SMS',):
                    self.feature_dict['read_sms_mms'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def receive_sms(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.RECEIVE_SMS',):
                    self.feature_dict['receive_sms'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def change_network_state(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.CHANGE_NETWORK_STATE',):
                    self.feature_dict['change_network_state'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def interact_accross_user_full(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.INTERACT_ACROSS_USERS_FULL',):
                    self.feature_dict['interact_accross_user_full'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def broadcast_sticky(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.BROADCAST_STICKY',):
                    self.feature_dict['broadcast_sticky'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def write_setting(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.WRITE_SETTINGS',):
                    self.feature_dict['write_setting'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def get_running_task(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.GET_TASKS',):
                    self.feature_dict['get_running_task'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def system_level_alert(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.SYSTEM_ALERT_WINDOW',):
                    self.feature_dict['system_level_alert'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def receive_boot_completed(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.RECEIVE_BOOT_COMPLETED',):
                    self.feature_dict['receive_boot_completed'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def read_calendar(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.READ_CALENDAR',):
                    self.feature_dict['read_calendar'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def write_calendar(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.WRITE_CALENDAR',):
                    self.feature_dict['write_calendar'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass




    # def system_alert_window(self):
    #         pass

    def wake_lock(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.WAKE_LOCK',):
                    self.feature_dict['wake_lock'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def read_history_bookmark(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'].find('READ_HISTORY_BOOKMARKS') != -1 :
                    self.feature_dict['read_history_bookmark'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def write_history_bookmark(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'].find('WRITE_HISTORY_BOOKMARKS') != -1:
                    self.feature_dict['write_history_bookmark'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def read_phone_state(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.READ_PHONE_STATE',):
                    self.feature_dict['read_phone_state'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass



    # def get_tasks(self):
    #     pass

    def access_camera(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.CAMERA',):
                    self.feature_dict['access_camera'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def read_external_storage(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.READ_EXTERNAL_STORAGE',):
                    self.feature_dict['read_external_storage'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def read_logs(self):
        try:
            for each in self.analysis_data['apkinfo']['manifest']['permissions']:
                if each['name'] in ('android.permission.READ_LOGS',):
                    self.feature_dict['read_logs'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    # def install_shortcut(self):
    #     pass

    # Finger printing
    def MAC_address(self):
        try:
            for each in self.analysis_data['droidmon']['fingerprint']:
                if each in ("getMacAddress",):
                    self.feature_dict['MAC_address'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def Network_Operator(self):
        try:
            for each in self.analysis_data['droidmon']['fingerprint']:
                if each in ("getNetworkOperator",):
                    self.feature_dict['Network_Operator'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def Device_ID(self):
        try:
            for each in self.analysis_data['droidmon']['fingerprint']:
                if each in ("getDeviceId",):
                    self.feature_dict['Device_ID'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def Sim_serial_Number(self):
        try:
            for each in self.analysis_data['droidmon']['fingerprint']:
                if each in ("getSimSerialNumber",):
                    self.feature_dict['Sim_serial_Number'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def Sim_Operator_Name(self):
        try:
            for each in self.analysis_data['droidmon']['fingerprint']:
                if each in ("getSimOperatorName",):
                    self.feature_dict['Sim_Operator_Name'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def get_network_country(self):
        try:
            for each in self.analysis_data['droidmon']['fingerprint']:
                if each in ("getNetworkCountryIso",):
                    self.feature_dict['get_network_country'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def sim_iso_country(self):
        try:
            for each in self.analysis_data['droidmon']['fingerprint']:
                if each in ("getSimCountryIso",):
                    self.feature_dict['sim_iso_country'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def get_line_number(self):
        try:
            for each in self.analysis_data['droidmon']['fingerprint']:
                if each in ("getLine1Number",):
                    self.feature_dict['get_line_number'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    # Broadcast receiver
    def screen_On(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('SCREEN_ON') != -1:
                    self.feature_dict['screen_On'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def screen_off(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('SCREEN_OFF') != -1:
                    self.feature_dict['screen_off'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def package_added(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('PACKAGE_ADDED') != -1:
                    self.feature_dict['package_added'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def package_removed(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('PACKAGE_REMOVED') != -1:
                    self.feature_dict['package_removed'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def SMS_received(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('SMS_RECEIVED') != -1 or each.find('GSM_SMS_RECEIVED') != -1:
                    self.feature_dict['SMS_received'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def SMS_delivered(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('SMS_RECEIVED') != -1:
                    self.feature_dict['SMS_delivered'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    # def device_admin_enabled(self):
    #     try:
    #         for each in self.analysis_data['droidmon']['registered_receivers']:
    #             if each.find('') != -1:
    #                 self.feature_dict['device_admin_enabled'] = 1
    #     except KeyError:
    #         pass
    #     except:
    #         traceback.print_exc()
    #         pass

    def boot_completed(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('BOOT_COMPLETED') != -1:
                    self.feature_dict['boot_completed'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def action_power_connected(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('ACTION_POWER_CONNECTED') != -1:
                    self.feature_dict['action_power_connected'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def action_power_disconnected(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('ACTION_POWER_DISCONNECTED') != -1:
                    self.feature_dict['action_power_disconnected'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def battery(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('BATTERY_OKAY') != -1 or each.find('BATTERY_CHANGED') != -1:
                    self.feature_dict['battery'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def user_present(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('USER_PRESENT') != -1:
                    self.feature_dict['user_present'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def media_changes(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('MEDIA_REMOVED') != -1 or each.find('MEDIA_UNMOUNTED') != -1 or each.find('MEDIA_BAD_REMOVAL') != -1:
                    self.feature_dict['media_changes'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def head_set_detect(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('HEADSET_PLUG') != -1:
                    self.feature_dict['head_set_detect'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def proxy_change(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('PROXY_CHANGE') != -1:
                    self.feature_dict['proxy_change'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def connectivity_change(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('CONNECTIVITY_CHANGE') != -1:
                    self.feature_dict['connectivity_change'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass


    def baidu_detect_root(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('com.baidu.appsearch.action.ROOTREQUESTFAILED') != -1 or each.find('com.baidu.appsearch.action.ROOTREQUESTSUCCESS') != -1:
                    self.feature_dict['baidu_detect_root'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def baidu_silent_install(self):
        try:
            for each in self.analysis_data['droidmon']['registered_receivers']:
                if each.find('com.baidu.appsearch.action.SILENTINSTALLSTART') != -1 or each.find('com.baidu.appsearch.action.SILENTINSTALLSUCCESS') != -1:
                    self.feature_dict['baidu_silent_install'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass
    # Static Method/function calls
    def cypto_function(self):
        try:
            if len(self.analysis_data["apkinfo"]["static_method_calls"]["crypto_method_calls"]) > 0:
                self.feature_dict['cypto_function'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def contact_read(self):
        try:
            for each in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                if each in ("READ_CONTACTS",):
                    self.feature_dict['contact_read'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def camera(self):
        try:
            for each in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                if each in ("CAMERA",):
                    self.feature_dict['camera'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def bookmark(self):
        try:
            for each in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                if each in ("WRITE_HISTORY_BOOKMARKS",):
                    self.feature_dict['bookmark'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def location(self):
        try:
            for each in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                if each in ("ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION",):
                    self.feature_dict['location'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def send_sms(self):
        try:
            for each in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                if each in ("SEND_SMS",):
                    self.feature_dict['send_sms'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    #some logics which indicates suspecious behaviour

        #1 set wall paper + location + read logs
    def location_wallpaper_readlogs(self):
        try:
            if "SET_WALLPAPER" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                if "ACCESS_FINE_LOCATION" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                    if "READ_LOGS" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                        self.feature_dict['location_wallpaper_readlogs'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def credential_killProcess_audioRecord_camera_location_internet(self):
        try:
            if "USE_CREDENTIALS" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                if "KILL_BACKGROUND_PROCESSES" in self.analysis_data["apkinfo"]["static_method_calls"][
                    "permissions_method_calls"]:
                    if "RECORD_AUDIO" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                        if "CAMERA" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                            if "ACCESS_FINE_LOCATION" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"] or "ACCESS_COARSE_LOCATION" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                                if "INTERNET" in self.analysis_data["apkinfo"]["static_method_calls"]["permissions_method_calls"]:
                                    self.feature_dict['location_wallpaper_readlogs'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    # Network forensics
    def IP_address_blacklisted(self):
        try:
            for each in self.vt_ip_result["vt_ipvoid_ip"]:
                if each["ipvoid_result"]["Blacklist Status"] == 1:
                    self.feature_dict['IP_address_blacklisted'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def IP_address_belongs_high_severity_country(self):
        try:
            for each in self.vt_ip_result["vt_ipvoid_ip"]:
                if each["ipvoid_result"]["Country Code"] in (" (CN) China",):
                    self.feature_dict['IP_address_belongs_high_severity_country'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

        try:
            for each in self.vt_ip_result["vt_ipvoid_ip"]:
                if each["vt_result"]["country"] in ("CN","RU","AT","BR","HK","IR","IQ","KP","KZ","RU","UA"):
                    self.feature_dict['IP_address_belongs_high_severity_country'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def IP_address_hosting_flaged_url_on_Virustotal(self):
        try:
            for each in self.vt_ip_result["vt_ipvoid_ip"]:
                for each_1 in each["vt_result"]["detected_urls"]:
                    try:
                        if each_1["positives"] > 3:
                            self.feature_dict['IP_address_hosting_flaged_url_on_Virustotal'] = 1
                    except:
                        continue
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def IP_address_hosting_malicous_files_on_Virustotal(self):
        try:
            for each in self.vt_ip_result["vt_ipvoid_ip"]:
                for each_1 in each["vt_result"]["detected_downloaded_samples"]:
                    try:
                        if each_1["positives"] > 3:
                            self.feature_dict['IP_address_hosting_malicous_files_on_Virustotal'] = 1
                    except:
                        continue
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    # def DNS_request_for_domain_flaged_by_Virustotal(self):
    #     try:
    #         for each in self.vt_ip_result["vt_url_scan"]:
    #             if each["vt_result"]["country"] in ("CN",):
    #                 self.feature_dict[''] = 1
    # except KeyError:
    pass
    # except:
    #         pass

    def URL_flaged_on_virustotal(self):
        try:
            for each in self.vt_ip_result["vt_url_scan"]:
                if each["vt_result"]["positives"] > 2:
                    self.feature_dict['URL_flaged_on_virustotal'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def ethernet_frames(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "eth":
                    self.feature_dict['ethernet_frames'] = int(each["frames"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def ethernet_bytes(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "eth":
                    self.feature_dict['ethernet_bytes'] = int(each["bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def arp_frames(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "arp":
                    self.feature_dict['arp_frames'] = int(each["frames"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def arp_bytes(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "arp":
                    self.feature_dict['arp_bytes'] = int(each["bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def ip_frames(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "ip":
                    self.feature_dict['ip_frames'] = int(each["frames"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def ip_bytes(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "ip":
                    self.feature_dict['ip_bytes'] = int(each["bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def udp_frames(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "udp":
                    self.feature_dict['udp_frames'] = int(each["frames"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def udp_bytes(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "udp":
                    self.feature_dict['udp_bytes'] = int(each["bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def tcp_frames(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "tcp":
                    self.feature_dict['tcp_frames'] = int(each["frames"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def tcp_bytes(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "tcp":
                    self.feature_dict['tcp_bytes'] = int(each["bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def dns_frames(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "dns":
                    self.feature_dict['dns_frames'] = int(each["frames"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def dns_bytes(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "dns":
                    self.feature_dict['dns_bytes'] = int(each["bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def irc_frames(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "irc":
                    self.feature_dict['irc_frames'] = int(each["frames"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def irc_bytes(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "irc":
                    self.feature_dict['irc_bytes'] = int(each["bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def smtp_frames(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "smtp":
                    self.feature_dict['smtp_frames'] = int(each["frames"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def smtp_bytes(self):
        try:
            for each in self.analysis_data["input_output_protocol_hirarchy"]:
                if each["protocol_name"] == "smtp":
                    self.feature_dict['smtp_bytes'] = int(each["bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def udp_uploaded_data(self):
        try:

            for each in self.analysis_data["udp_conversation"]:
                if each["external_ip"] not in ("8.8.4.4","8.8.8.8"):
                    self.feature_dict['udp_uploaded_data'] = self.feature_dict['udp_uploaded_data'] + int(each["upload_bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def udp_downloaded_data(self):
        try:

            for each in self.analysis_data["udp_conversation"]:
                if each["external_ip"] not in ("8.8.4.4", "8.8.8.8"):
                    self.feature_dict['udp_downloaded_data'] = self.feature_dict['udp_downloaded_data'] + int(each[
                        "download_bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def tcp_uploaded_data(self):
        try:

            for each in self.analysis_data["tcp_conversation"]:
                self.feature_dict['tcp_uploaded_data'] = self.feature_dict['tcp_uploaded_data'] + int(each["upload_bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def tcp_downloaded_data(self):
        try:

            for each in self.analysis_data["tcp_conversation"]:
                self.feature_dict['tcp_downloaded_data'] = self.feature_dict['tcp_downloaded_data'] + int(each[
                    "download_bytes"])
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def udp_coversation_average_data_transfer_rate(self):
        try:
            total_time = 0.00000
            total_bytes_transfered = 0
            for each in self.analysis_data["udp_conversation"]:
                total_time = total_time + float(each["duration"])
                total_bytes_transfered = total_bytes_transfered + int(each["total_bytes"])
            if total_time != 0.00000:
                self.feature_dict['udp_coversation_average_data_transfer_rate'] = float(float(total_bytes_transfered) / float(total_time))
            else:
                self.feature_dict['udp_coversation_average_data_transfer_rate'] = 0.00000
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def tcp_coversation_average_data_transfer_rate(self):
        try:
            total_time = 0.00000
            total_bytes_transfered = 0
            for each in self.analysis_data["tcp_conversation"]:
                total_time = total_time + float(each["duration"])
                total_bytes_transfered = total_bytes_transfered + int(each["total_bytes"])

            if total_time != 0.00000:
                self.feature_dict['tcp_coversation_average_data_transfer_rate'] = float( float(total_bytes_transfered) / float(total_time))
            else:
                self.feature_dict['tcp_coversation_average_data_transfer_rate'] = 0.00000
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def snort_alert_for_malaware_related_activity(self):
        try:
            for each in self.snort_data["snort_logs"]:
                if each["Classification"] == "trojan-activity":
                    self.feature_dict['snort_alert_for_malaware_related_activity'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def snort_alert_for_exploit_kit_activity(self):
        try:
            for each in self.snort_data["snort_logs"]:
                if each["summary"].find("exploitkit") != -1:
                    self.feature_dict['snort_alert_for_exploit_kit_activity'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass

    def snort_high_severity_alert(self):
        try:
            for each in self.snort_data["snort_logs"]:
                if each["Priority"] == 1:
                    self.feature_dict['snort_high_severity_alert'] = 1
        except KeyError:
            pass
        except:
            traceback.print_exc()
            pass



if __name__ == "__main__":
    local_mdb = my_mdb()
    # "current_analysis_layer":""
    # "current_analysis_layer":"layer_4_a"
    local_mdb.cl_analysis_tickets.find().batch_size(10)

    # "current_analysis_layer":"layer_3_snort_exc"/ "current_analysis_layer":"layer_4_a"

    tickets = local_mdb.cl_analysis_tickets.find({"current_analysis_layer":"layer_4_a"})
    if tickets.count()!=0:
        for each in tickets:
            ticket = objects_ASX.ticket(each)
            print magenta(" Working on malware_ticket ticket_id : %s" % (ticket.ticket_id))
            ai_features(ticket)
    else:
        print green("No tickets with current_analysis_layer = layer_3_snort_exc")
    # #----------- This is during training, we have a perfect featureset now no need to rerun
    # malware_tickets = local_mdb.cl_analysis_tickets.find({"ai_decision.analysis_conclusion":"malware","current_analysis_layer":"layer_4_a"})
    # benign_tickets = local_mdb.cl_analysis_tickets.find({"ai_decision.analysis_conclusion":"benign","current_analysis_layer":"layer_4_a"})
    #
    # if malware_tickets.count()!=0:
    #     for each in malware_tickets:
    #         ticket = objects_ASX.ticket(each)
    #         print magenta(" Working on malware_ticket ticket_id : %s"%(ticket.ticket_id))
    #         ai_features(ticket)
    #
    #
    # print(red("\n\n===================== Sleeping 60 Sec ============================\n\n"))
    # time.sleep(60)
    #
    # if benign_tickets.count()!=0:
    #     for each in benign_tickets:
    #         ticket = objects_ASX.ticket(each)
    #         print magenta(" Working on benign_ticket ticket_id : %s" % (ticket.ticket_id))
    #         ai_features(ticket)
    #
    # #----------- End of training feature creation part

