#!/usr/bin/python
import socket
import threading
import sys
import time
import os
import email.utils
import binascii
from uuid import uuid4

import mimetypes
# global variables
serverIP = '127.0.0.1'
serverPort = 12001
CRLF = '\r\n'

import statusCode
import config

# create response
# SHOULD headers in response
response = {
	'version': 'HTTP/1.1',
	'status_code' : 200,
	'status_msg': 'OK',
	'Date': '',
	'Server': 'http-Server',			# Server: CERN/3.0 libwww/2.17
	'Content-Type':'text/html',
	'Content-Length': 0
}

# All HTTP date/time stnps MUST be represented in Greenwich Mean Time (GMT), without exception.
# email.utils.formatdate(timeval=None, localtime=False, usegmt=False)
def date_time_format(local_time = False):
	return email.utils.formatdate(timeval = None, localtime = local_time, usegmt = False)


#server will create a cookie 
#create a random number - save in file and necessary info 
#on client request identify if this is 1st access or no
def createCookie(ip_addr, http_resp):
	cookie_dict = dict()
	# Set-Cookie: <em>value</em>[; expires=<em>date</em>][; domain=<em>domain</em>][; path=<em>path</em>][; secure]
	cookiedir = config.CookieDir
	cookiefile = config.CookieFile
	# if cookie directory and file not present then create
	if not os.path.exists(cookiedir):
		os.mkdir(cookiedir)
	if not os.path.exists(cookiefile):
		f = open(cookiefile, 'w')
		f.close()
	# load the text file into dictionary
	try:
		with open(cookiefile, 'r') as cfile:
			for line in cfile:
				pairs = line.strip('{').strip('\n').strip('}').split(':')
				client_ip, cookie_id = [i.strip().strip("'") for i in pairs]
				# dictionary{ key (ip) : value (cookie) }
				cookie_dict[client_ip] = cookie_id	
	except Exception as e:
		print("\nError creating file", e)
	#print("\nCookie_dict = ", cookie_dict)
	# cookie dictionary is created
	# check if already cookie present
	if cookie_dict.get(ip_addr, None) is None:
		# create new cookie
		cookie_id = str(uuid4())
		client_ip = str(ip_addr)
		#print('{ ' + '{}: {}'.format(client_ip, cookie_id) + ' }')
		with open(cookiefile, 'a') as cfile:
			cfile.write('{ ' + '{}: {}'.format(client_ip, cookie_id) + ' }\n')
		return cookie_id
	else:
		# already present - return cookie_id
		return cookie_dict.get(ip_addr)
	

# status code 404 - html message
def error_display(http_resp):
	flag = False
	msg = ''
	if http_resp['status_code']//100 != 2:
		flag = True
		msg = '<html><h2>{}: {}</h2></html>'.format(http_resp['status_code'], statusCode.get_status_code(http_resp['status_code']))
		http_resp['Content-Length'] = len(msg)
		http_resp['Content-Type'] = 'text/html'
	return msg, flag

# add required parameters
# need method for POST, PUT
def createResponse(ip, http_resp, method, cType= 'text/html', cLength = 0):
	#response['statusCode'] = statusCode			# already added outside
	#response['statusResp'] = statusCode.get_status_code(statusCode)
	http_resp['Date'] = str(date_time_format(False))
	http_resp['Content-Type'] = cType
	http_resp['Content-Length']=cLength
	m, flag = error_display(http_resp)
	if not flag:
		http_resp['Set-Cookie'] = createCookie(ip, http_resp)
	if len(m)> 0:	
		http_resp['Content-Length'] = len(m)
	http_response = ""
	first_line = ''
	for key, value in http_resp.items():
		if key in ['version', 'status_code', 'status_msg']:
			first_line +=str(value) + ' '
		else:
			http_response += CRLF
			http_response += str(key) + ": " + str(value)
	http_response += CRLF + CRLF + m
	http_response = first_line + http_response
	#print("http-response=\n",http_response)
	return http_response


# [time] [client-ip] [pid] [request] [response]
def AccessLog(ip, http_resp, method, abs_path):
	date = str(date_time_format(True))
	req_line = str(method) + ' ' + str(abs_path) + ' ' + str(http_resp.get('version')) 
	resp_line = str(http_resp.get('status_code')) +' '+ str(http_resp.get('status_msg'))
	pid = str(os.getpid())
	accesslog = '[{}] [{}] [pid {}] [{}] [{}]'.format(date, ip, pid, req_line, resp_line)  
	
	# avoid overeriding or not updated info in shared file
	lock = threading.lock()

	# check if access log file exists
	try:
		lock.aquire()
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
	lock = threading.lock()
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
#def ServerError(status_code = 500, error = ''):
	
	

# returns method, abs_path, httpversion, headers, msg
def splitRequest(http_resp, client_socket, recv_msg):
	request = recv_msg.decode('ISO-8859-1') 	# default charset
	r =  request.split('\r\n\r\n')
	req_body = r[1:]
	r = r[0]
	r = r.split(CRLF)
	req_line = r[0]
	headers = r[1: ]	# till the CRLF is identified
	first_line = req_line.split(' ')
	method, abs_path, version = first_line
	method = method.strip()
	abs_path = abs_path.strip()
	version = version.strip()
	headers_dict = {}
	req_body = ''
	for i in headers:
		try:
			hfield, hvalue = i.split(':', 1)	
			hfield = hfield.strip()
			hvalue = hvalue.strip()
			headers_dict[hfield] = hvalue
		except:
			continue
	# if post or put method
	# if method is post or put then message body is present or else it is empty
	# length of message mat be larger, recv in loop
	if method in ['POST', 'PUT']:
		received_length = int(len(recv_msg))
		remaining_length = 0
		remaining_data = b''
		
		# SHOULD condition 
		if headers_dict.get('Content-Length') is None:
			http_resp['status_code'] = 411
			http_resp['status_msg'] = statusCode.get_status_code(411)
			# error log
			return method, abs_path, version, headers_dict, req_body

		clength = int(headers_dict.get('Content-Length'))
		print("Content length = ", clength)
		while True:
			remaining_length = clength - received_length
			if remaining_length < 0:
				break
			remaining_data = client_socket.recv(4096)
			if not remaining_data:
				break
			recv_msg = recv_msg + remaining_data
			received_length = int(len(recv_msg))
		# now entire message is received
		print("Length of received data =",received_length)
		#print("\n\nmessage with extra data =",remaining_data)
		req_body = recv_msg.split(b'\r\n\r\n')[1:]
		delimiter = b'\r\n'
		req_body = delimiter.join(req_body)
	return method, abs_path, version, headers_dict, req_body
	
# incomplete
def checkAcceptHeader(http_resp, accept_type, resp_type):
	# split accept header by priority in list
	accept_list = accept_type.split(',')
	accept = []
	for a in accept_list:
		try:
			j = a.split(';')
			if len(j) > 1:
				accept.append([((j[1]).split('='))[-1], j[0]])
			else:
				accept.append([1, j[0]])
		except:
			continue
	accept.sort(key=lambda x: int(x[0]))
	# check if resp_type in it
	if resp_type not in accept_list:	
		http_resp['status_code'] = 406
		http_resp['status_msg'] = statusCode.get_status_code(406)
		return False
	return True


# mimetype - import mimetype
#returns data for Content-Type header
# for other file types - change this!!
def get_ctype(filename):
	# extension --> content-type
	# html --> text/html
	# png-->image/png
	#  jpeg --> image/jpeg
	# jpg --> image.jpg
#	text/css    
#	text/csv    
#	text/html    
#	text/javascript 
#	text/plain    
#	text/xml    
	return mimetypes.MimeTypes().guess_type(filename)[0]

# for images open file in binary
# return get response with file
def GET_Request(ip, http_resp, method, abs_path, httpversion, headers):
#	print(f"Method:{method}\nabs_path:{abs_path}\nversion:{httpversion}")
#	print("Headers:")
#	for k, v in headers.items():
#		print(k, v)
	# start with abs_path
	# if no specific file return index.html
	fileExtension = ''	# needed for content-type
	file_path = ''
	filedata = ''
	try:
		if '.' in abs_path:
			fileExtension = (abs_path.split('.'))[-1]
		else:
			fileExtension = 'html'
		
		# for images open file in binary

		# check if file present or no - give404 not found error
		p = config.ServerRoot + config.FetchFile + abs_path
		if os.path.isdir(p):
			if (p.strip())[-1] != '/':
				# then get the index.html file present
				p = p + '/'
			p=p+'index.html'

		filename = (p.split('/')[-1]).strip()
		# check if the file exists
		if not os.path.isfile(p):
			# 404 not found error
			http_resp['status_code'] = 404
			http_resp['status_msg'] = statusCode.get_status_code(404)
		else:	
			# file has been found send the file as message
			# check permission - file is readable
			if not os.access(config.FetchFile + abs_path, os.R_OK):
				http_resp['status_code'] = 403
				http_resp['status_msg'] = statusCode.get_status_code(403)
			else:
				with open(p, 'rb') as f:
					for bline in f:
						try:
							line = bline.decode('utf-8')	
							filedata += line
						except UnicodeDecodeError as ex:
							print("ignore")
					
	except Exception as e:
		print("GET request error")
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		print(e)
			
	resp = createResponse(ip, http_resp, method, get_ctype(filename), len(filedata)) + filedata
	return resp


def HEAD_Request(ip, http_resp, method, abs_path, httpversion, headers):
	fileExtension = ''	
	file_path = ''
	filedata = ''
	if '.' in abs_path:
		fileExtension = (abs_path.split('.'))[-1]
	else:
		fileExtension = 'html'
	# check if file present or no - give404 not found error
	p = config.ServerRoot + config.FetchFile + abs_path
	if os.path.isdir(p):
		if (p.strip())[-1] != '/':
			# then get the index.html file present
			p = p + '/'
		p=p+'index.html'

	filename = (p.split('/')[-1]).strip()
	# check if the file exists
	if not os.path.isfile(p):
		# 404 not found error
		http_resp['status_code'] = 404
		http_resp['status_msg'] = statusCode.get_status_code(404)
	else:	
		# file has been found send the file as message
		# check permission - file is readable
		if not os.access(config.FetchFile + abs_path, os.R_OK):
			http_resp['status_code'] = 403
			http_resp['status_msg'] = statusCode.get_status_code(403)
		else:
			try:
				with open(p, 'r') as f:
					for line in f:
						filedata += line

			except Exception as e:
				# 404 not found error
				print("Head request error")
				print(e)
				http_resp['status_code'] = 404
				http_resp['status_msg'] = statusCode.get_status_code(404)
				filedata = ''
	resp = createResponse(ip, http_resp, method, get_ctype(filename), len(filedata))
	return resp

# A POST request is typically sent via an HTML form and results in a change on the server.
def POST_Request(ip, http_resp, method, abs_path, httpversion, headers, req_body = b''):
	"""	
	print(f"Method:{method}\nabs_path:{abs_path}\nversion:{httpversion}\nrequest body:{req_body}")
	print("Headers:")
	for k, v in headers.items():
		print(k, v)

	print("Request body:")
	print(len(req_body.split(b'\r\n')))
	for i in req_body.split(b'\r\n'):
		print(i)
	"""
	formData = {}		# save as key value pair
	field_name = filename = field_value = None
	filedata = req_body
	# check the Content-Type header to decide the type
	# content-type exists in header
	try:
		if headers.get('Content-Type') is not None:
			ctype = headers.get('Content-Type')
			if 'application/x-www-form-urlencoded' in ctype:
				print("application/x-www")
				for pair in req_body.split(b'&'):
					print(pair)	
					if b'+' in pair:
						# replaces all occurences in pair
						pair.replace(b'+', b' ')	
					if b'%' in pair:
						c = pair.count(b'%')
						index = 0
						for i in range(c):
							index = pair.find(b'%', index)	
							v = binascii.hexlify(pair[index + 1 : index + 3])
							r = bytes.fromhex(v)
							pair.replace(v, r)
					field_name, field_value = pair.split(b'=')
					formData[field_name] = field_value
						 
			elif 'multipart/form-data' in ctype:
				boundary = ctype[ctype.rfind('-')+1:].strip()
				# better way
				for line in req_body.split(bytes(boundary, 'ISO-8859-1')):
					if b'Content-Disposition: form-data' in line:
						if b'filename' in line:
							field_name = line[line.index(b'name=')+5 : line.find(b';', line.find(b';') + 1)].decode('ISO-8859-1')
							filename = line[line.index(b'filename=')+9 : line.find(b'\r\n', line.find(b'filename'))].decode('ISO-8859-1')
							ctype = line[line.index(b'Content-Type') + 15 : line.find(b'\r\n', line.find(b'Content-Type')) + 1].decode('ISO-8859-1')
							# start index of file_data							
							file_data_index = line.find(b'\r\n', line.find(b'Content-Type')) + 2		
							filedata = line[file_data_index : line.find(b'----')]		#did not decode
							field_value = filename
						else:
							field_name = line[line.index(b'name=')+5 :  line.find(b'\r\n', line.find(b'name=') + 1)].decode()
							field_value = line[line.find(b'\r\n', line.find(b'name') + 1) + 2 : line.find(b'\r\n', line.find(b'\r\n', line.find(b'name') + 1)+ 1)].decode()
							#print(field_name, field_value)
						formData[field_name.strip()] = field_value.strip()
					else:
						continue		
			elif 'text/plain' in ctype:
				index = 0
				for body in req_body:
					index += 1
					key, value = body.split(b"=")
					formData[key] = value
				filedata = req_body[:]
						
	except Exception as e:
		print("Post requets error")
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		print(e)
	# data fetched successfully
	print("File content =",filedata)
	for k, v in formData.items():
		print(f'{k}={v}')

	###########################################################################
	# check abs_path and loaction for storing the data from request
	fileExtension = ''
	fileMode = 'a'
	try:
		# for images open file in binary
		# fileMode= 'ab'
		
		# check if file present or no - give404 not found error
		p = config.ServerRoot + config.StoreFile + abs_path
		# check if path present or else create one
		if not os.path.isdir(p):
			os.mkdir(p)
		if (p.strip())[-1] != '/':
			p = p + '/'
		# store in this file
		p=p+'post_request.txt'

		filename = (p.split('/')[-1]).strip()
		# check if the file exists or create
		#if not os.path.isfile(p):
		mfile = open(p, fileMode)
		# file has been found  or created
		# check permission - file is writable - forbidden error
		if not os.access(p, os.W_OK):
			http_resp['status_code'] = 403
			http_resp['status_msg'] = statusCode.get_status_code(403)
			return createResponse(ip, http_resp, method, get_ctype(filename), len(filedata)) 
					
		###########################################################################
		
		# log format - similar store in file
		post_log = '\n\n'
		# make changes to add ip address
		post_log += '[' + date_time_format(True) + '] '
		post_log += '[' + http_resp.get('version') +' '+ str(http_resp.get('status_code')) +' '+ http_resp.get('status_msg')+']\n'
		for k, v in formData.items():
			post_log += k + ': ' + v + '\n'
		post_log += 'file-data: ' 
		mfile.write(post_log)
		mfile.write(str(filedata))	#think
		mfile.close()
		
	except Exception as e:
		print("Post request error")
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		print(e)

	post_response = '<html><h2>POST Request Successful!!!</h2></html>'
	resp = createResponse(ip, http_resp, method, 'text/html', len(post_response)) + post_response
	return resp

def PUT_Request(ip, http_resp, method, abs_path, httpversion, headers, req_body = b''):
	#update an existing resource on the server
	pass


def DELETE_Request(ip, http_resp, method, abs_path, httpversion, headers):
	#A successful response MUST be 200 (OK) if the server response includes a message body, 
	# 202 (Accepted) if the DELETE action has not yet been performed, or 
	#204 (No content) if the DELETE action has been completed but the response does not have a message body.
	# restricting the files or folders to be deleted to one folder
	path = config.ServerRoot + config.FetchFile + '/deletefiles'
	fileExtension = ''
	filename =''
	if '.' in abs_path:
		fileExtension = (abs_path.split('.'))[-1]
	else:
		fileExtension = 'txt'
	
	# check if file present or no - give404 not found error
	p = path + abs_path
	# entire directory is to be deleted
	if os.path.isdir(p):
		if (p.strip())[-1] != '/':
			# then delete the text.txt file present
			p = p + '/'
		p=p+'test.txt'

	filename = (p.split('/')[-1]).strip()
	# check if the file exists
	if not os.path.isfile(p):
		# 404 not found error
		http_resp['status_code'] = 404
		http_resp['status_msg'] = statusCode.get_status_code(404)
	else:	
		# file has been found
		# check permission - file is deletable
		if not os.access(p, os.W_OK):
			http_resp['status_code'] = 403
			http_resp['status_msg'] = statusCode.get_status_code(403)
		else:
			try:
				os.remove(p)
			except:
				#print("os.remove error")
				http_resp['status_code'] = 202
				http_resp['status_msg'] = statusCode.get_status_code(202)
				msg = '<html><body><h2>Delete request accepted!!!<br> 202 : Accepted</h2></body></html>'
				resp = createResponse(ip, http_resp, method, 'text/html', len(msg)) + msg
				return resp
			# successful deletion
			http_resp['status_code'] = 200
			http_resp['status_msg'] = statusCode.get_status_code(200)

	msg = '<html><body><h2>Delete request successful!!!</h2></body></html>'
	if http_resp.get('status_code') == 200:
		resp = createResponse(ip, http_resp, method, 'text/html', len(msg)) + msg
	else:
		resp = createResponse(ip, http_resp, method)
	return resp
				

	

# check for errors in request
# msg_body is for post put
# return True is request is valid 
# False for invalid, error
def checkRequest(http_resp, method, abs_path, httpversion, headers, req_body = ""):
	# error found in splitRequest function
	if http_resp['status_code'] != 200:
		return False
	if httpversion.strip() != 'HTTP/1.1':
		http_resp['status_code'] = 505
		http_resp['status_msg'] = statusCode.get_status_code(505)
		return False
	if method not  in ["GET", "POST", "PUT", "DELETE", "HEAD"]:
		http_resp['status_code'] = 501
		http_resp['status_msg'] = statusCode.get_status_code(501)
		return False
	return True

# keep alive or close
def connHeader():
	return True


# parse requests
# split request into method, path, version, headers, msg
def handleRequest(s, ip, recv_msg):
	global response
	print("Handle request function started . . . ")
	http_resp = response.copy()
	method, abs_path, httpversion, headers, req_body = splitRequest(http_resp, s, recv_msg)
	print(f"\nMethod:{method}\nabs_path:{abs_path}\nversion:{httpversion}\nrequest body:{req_body}")
	print("Headers:")
	for k, v in headers.items():
		print(k, v)
	
	isReqValid =checkRequest(http_resp, method, abs_path, httpversion, headers, req_body)
	try:
		if isReqValid:
			if method == 'GET':
				resp = GET_Request(ip, http_resp, method, abs_path, httpversion, headers)
				print(resp, type(resp))
			elif method == 'HEAD':
				resp = HEAD_Request(ip, http_resp, method, abs_path, httpversion, headers)
			elif method == 'POST':
				resp = POST_Request(ip, http_resp, method, abs_path, httpversion, headers, req_body)
			elif method == 'PUT':
				resp = PUT_Request(ip, http_resp, method, abs_path, httpversion, headers, req_body)
			elif method == 'DELETE':
				resp = DELETE_Request(ip, http_resp, method, abs_path, httpversion, headers)
		# request is not valid
		else:
			print("Invalid request")
			resp = createResponse(ip, http_resp, method)	# send parameters - make changes to function
	except Exception as e:
		print("Handle request error")
		print(e)
		http_resp['status_code'] = 500
		http_resp['status_msg'] = statusCode.get_status_code(500)
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		print(e)
		resp = createResponse(ip, http_resp, method)
		# add in error log
	return resp


def get_method(request):
	request = request.decode('ISO-8859-1')
	method = ((request.split(CRLF))[0]).split(' ')[0]
	return method.strip()
	


def clientRequests(client):
	s = client[0]
	ip = client[1]
	# if client dosen't send request in the given frame then close...otherwise keep connection open
	timeout = 10
	# which method requested
	# persistant or non-persistant connections
	while True:
		try:
			# receive request from client
			print("Receiving client message...")
			recv_msg = s.recv(4096)
			#print(request)

			response = handleRequest(s, ip[0], recv_msg)
			print("\nResponse:")
			print(response)
			s.send(response.encode('ISO-8859-1'))

			#s.close()	# for now testing - change
			# check the connection header - if alive or close
			# write a function to check this
			if connHeader():
				# decide what is true
				# close then true
				print("Socket is closing . . .")
				s.close()
				break
		except KeyboardInterrupt:
			print("Quitting . . .")
            		break
		except Exception as e:
#			print("Error: clientRequests function")
#			# add error log
#			exc_type, exc_obj, exc_tb = sys.exc_info()
#			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
#			print(exc_type, fname, exc_tb.tb_lineno)
			print(e)
			ErrorLog('error', e)
			break
	return

if __name__ == "__main__":
	serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	serverSocket.bind(('127.0.0.1',config.PORT))
	serverSocket.listen(100)
	print('The server is ready to receive...')

	# list to keep track of client threads
	client_threads = []

	while True:
		try:
			if threading.active_count() > config.MaxRequest:
				print("Server is busy\nRetry after few seconds . . .")
				time.sleep(5)
			clientSocket, addr = serverSocket.accept()
			client = (clientSocket, addr)
			print('\nNew request received from ', end=""); print(client[1]);
			th = threading.Thread(target = clientRequests, args = (client,))
			th.start()
			client_threads.append(th)
		except KeyboardInterrupt:
			print("Quitting . . .")
			break
		except Exception as e:
			print("\nserver error")
			ErrorLog('error', e)
			break
			
	# join threads 
	for t in client_threads:
		t.join()
	print("Successfully stopped server")
	serverSocket.close()
