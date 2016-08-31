#### Error login module ####
import datetime


def error_log(error_obj):
	file_handle = open("error_log.log","a")
	error_str = str(error_obj)
	error_str = '|%s| %s \n' % (datetime.datetime.now(),error_str)
	file_handle.write(error_str)
	file_handle.close()
	
