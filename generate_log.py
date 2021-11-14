from functions import *

# [time] [client-ip] [pid] [request] [response]
def AccessLog(ip, http_resp, method, abs_path):
	date = str(date_time_format(True))
	req_line = str(method) + ' ' + str(abs_path) + ' ' + str(http_resp.get('version')) 
	resp_line = str(http_resp.get('status_code')) +' '+ str(http_resp.get('status_msg'))
	pid = str(os.getpid())
	accesslog = '[{}] [{}] [pid {}] [{}] [{}]'.format(date, ip, pid, req_line, resp_line)  
	
	# avoid overriding or not updated info in shared file simultaneously
	lock = threading.Lock()

	# check if access log file exists
	try:
		lock.acquire()
		if not os.path.exists(config.LogFolder):
			os.mkdir(config.LogFolder)
		accessfile = config.AccessLog
		if not os.path.exists(accessfile):
			# creates a new empty file
			with open(accessfile, 'w+') as f:
				pass
	except Exception as e:
		http_resp['status_code'] = 500
		http_resp['status_msg'] = statusCode.get_status_code(500)
		ErrorLog(ip, http_resp, method, abs_path, 'error', "Error writing access log")
		return

	# clear the file after the size has exceeded a fixed length
	if os.path.getsize(accessfile) > 50000:
		open(accessfile,"w").close()

	with open(accessfile, 'a+') as f:
		f.write('\n')
		f.write(accesslog)
	lock.release()
	return
	

# Format = [time] [client-ip] [loglevel] [pid] [request] [response] [error_message]
def ErrorLog(ip, http_resp, method, abs_path, level = '', error = ''):
	date = str(date_time_format(True))
	req_line = str(method) + ' ' + str(abs_path) + ' ' + str(http_resp.get('version')) 
	resp_line = str(http_resp.get('version')) +' '+ str(http_resp.get('status_code')) +' '+ str(http_resp.get('status_msg'))
	pid = str(os.getpid())
	errorlog = '[{}] [{}] [{}] [pid {}] [{}] [{}] [{}]'.format(date, ip, level, pid, req_line, resp_line, error) 
	lock = threading.Lock()
	# check if access log file exists
	try:
		lock.acquire()
		if not os.path.exists(config.LogFolder):
			os.mkdir(config.LogFolder)
		errorfile = config.ErrorLog
		if not os.path.exists(errorfile):
			# creates a new empty file
			with open(errorfile, 'w+') as f:
				pass
	except Exception as e:
		ServerInternalError(500, "Error creating error log file")
		return
	
	# clear the file after the size has exceeded a fixed length
	if os.path.getsize(errorfile) > 50000:
		open(errorfile,"w").close()
	
	with open(errorfile, 'a+') as f:
		f.write('\n')
		f.write(errorlog)
	lock.release()
	return

# Server Error - occured in main functions - during accept client
def ServerInternalError(status_code = 500, error = ''):
	date = str(date_time_format(True))
	pid = str(os.getpid())
	status_msg = str(statusCode.get_status_code(status_code))
	status_code= str(status_code)
	errorlog = '[{}] [pid {}] [{} {}] [{}]'.format(date, pid, status_code, status_msg, error) 
	lock = threading.Lock()
	# check if access log file exists
	try:
		lock.acquire()
		if not os.path.exists(config.LogFolder):
			os.mkdir(config.LogFolder)
		errorfile = config.ErrorLog
		if not os.path.exists(errorfile):
			# creates a new empty file
			with open(errorfile, 'w+') as f:
				pass
	except Exception as e:
		return
	
	# clear the file after the size has exceeded a fixed length
	if os.path.getsize(errorfile) > 50000:
		open(errorfile,"w").close()

	with open(errorfile, 'a+') as f:
		f.write('\n')
		f.write(errorlog)
	lock.release()
	return 
