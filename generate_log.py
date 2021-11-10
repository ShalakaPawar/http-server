from functions import *

# [time] [client-ip] [pid] [request] [response]
def AccessLog(ip, http_resp, method, abs_path):
	date = str(date_time_format(True))
	req_line = str(method) + ' ' + str(abs_path) + ' ' + str(http_resp.get('version')) 
	resp_line = str(http_resp.get('status_code')) +' '+ str(http_resp.get('status_msg'))
	pid = str(os.getpid())
	accesslog = '[{}] [{}] [pid {}] [{}] [{}]'.format(date, ip, pid, req_line, resp_line)  
	
	# avoid overeriding or not updated info in shared file
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
		print(e)
		print('creating access log file')
		return

	with open(accessfile, 'a+') as f:
		f.write('\n')
		f.write(accesslog)
	lock.release()
	print(accesslog)
	return
	

# Format = [time] [client-ip] [loglevel] [pid] [request] [response] [error_message]
def ErrorLog(ip, http_resp, method, abs_path, level = '', error = ''):
	date = str(date_time_format(True))
	req_line = str(method) + ' ' + str(abs_path) + ' ' + str(http_resp.get('version')) 
	resp_line = str(http_resp.get('version')) +' '+ str(http_resp.get('status_code')) +' '+ str(http_resp.get('status_msg'))
	pid = str(os.getpid())
	errorlog = '[{}] [{}] [{}] [pid {}] [{}] [{}] [{}]'.format(date, ip, level, pid, req_line, resp_line, error) 
	print(errorlog)
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
		print(e)
		print('creating error log file')
		return
	
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
		print(e)
		print('creating error log file')
		return
	
	with open(errorfile, 'a+') as f:
		f.write('\n')
		f.write(errorlog)
	lock.release()
	return 
