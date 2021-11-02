#!/usr/bin/python
import socket
import threading
import sys
import time
import os
import email.utils

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

# status code 404 - html message
def error_display(http_resp):
	msg = ''
	if http_resp['status_code'] != 200:
		msg = '<html><h2>{}: {}</h2></html>'.format(http_resp['status_code'], statusCode.get_status_code(http_resp['status_code']))
	return msg

# add required parameters
# need method for POST, PUT
def createResponse(http_resp, method, cType= 'text/html', cLength = 0):
	#response['statusCode'] = statusCode			# already added outside
	#response['statusResp'] = statusCode.get_status_code(statusCode)
	http_resp['Date'] = str(date_time_format(False))
	http_resp['Content-Type'] = cType
	http_resp['Content-Length']=cLength
	m = error_display(http_resp)
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

# returns method, abs_path, httpversion, headers, msg
def splitRequest(client_socket, recv_msg):
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
		clength = int(headers_dict.get('Content-Length', 0))
		print("Content length = ", clength)
		while True:
			remaining_length = clength - received_length
			if remaining_length <0:
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

#server will create a cookie 
#create a random number - save in file and necessary info 
#on client request identify if this is 1st access or no
def createCookie(ip_addr, http_resp):
	# Set-Cookie: <em>value</em>[; expires=<em>date</em>][; domain=<em>domain</em>][; path=<em>path</em>][; secure]
	value =  str(random.randint(1, 150000))
	expiry = 0	# change this
	return

# for images open file in binary
# return get response with file
def GET_Request(http_resp, method, abs_path, httpversion, headers):
	print(f"Method:{method}\nabs_path:{abs_path}\nversion:{httpversion}")
	print("Headers:")
	for k, v in headers.items():
		print(k, v)
	# start with abs_path
	# if no specific file return index.html
	fileExtension = ''	# needed for content-type
	file_path = ''
	filedata = ''
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
			http_resp['status_code'] = 404
			http_resp['status_msg'] = statusCode.get_status_code(404)
		else:
		
			with open(p, 'r') as f:
				for line in f:
					filedata += line

		
	resp = createResponse(http_resp, method, get_ctype(filename), len(filedata)) + filedata
	return resp


def HEAD_Request(http_resp, method, abs_path, httpversion, headers):
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
	resp = createResponse(http_resp, method, get_ctype(filename), len(filedata))
	return resp

# A POST request is typically sent via an HTML form and results in a change on the server.
def POST_Request(http_resp, method, abs_path, httpversion, headers, req_body = b''):
	"""print(f"Method:{method}\nabs_path:{abs_path}\nversion:{httpversion}\nrequest body:{req_body}")
	print("Headers:")
	for k, v in headers.items():
		print(k, v)
"""
	print("Request body:")
	print(len(req_body.split(b'\r\n')))
	for i in req_body.split(b'\r\n'):
		print(i)

	# check the Content-Type header to decide the type
	# content-type exists in header
	try:
		if headers.get('Content-Type') is not None:
			ctype = headers.get('Content-Type')
			if 'application/x-www-form-urlencoded' in ctype:
				 print()
			
			if 'multipart/form-data' in ctype:
				boundary = ctype[ctype.rfind('-')+1:].strip()
				fields=0
				print("Boundary = {",boundary, "}, ", type(boundary))
				# Content-Disposition: form-data; name="bat"
				# Content-Disposition: form-data; name="filename"; filename="1.odt"
				temp = False
				req_body_split = req_body.split(b'\r\n')
				for line in :
					#print("Line = ", line)
					if line.find(bytes('----' + boundary, 'utf-8')) != -1:
						#print("boundary line")
						fields += 1
						continue
					elif b'Content-Disposition' in line:
						temp=True		# to capture the next line
						print("Content-Disposition=",end='')
						content_disposition = line[line.index(b':')+2:line.index(b';')].strip().decode()		# saved as string
						print(content_disposition)		
						field_name = line[line.index(b'name=')+5:].decode()
						print("field name =",end='')
						print(field_name, type(field_name))
						#print(line + 1)
						#field_value = line + 1
					elif temp:
						temp = True
						
						
				
			if 'text/plain' in ctype:		
				print()
	except Exception as e:
		print("Post requets error")
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		print(e)
	return ''

def PUT_Request(http_resp, method, abs_path, httpversion, headers, req_body = b''):
	#update an existing resource on the server
	pass


def DELETE_Request(http_resp, method, abs_path, httpversion, headers):
	#A successful response MUST be 200 (OK) if the server response includes a message body, 
	# 202 (Accepted) if the DELETE action has not yet been performed, or 
	#204 (No content) if the DELETE action has been completed but the response does not have a message body.

	pass

# check for errors in request
# msg_body is for post put
# return True is request is valid 
# False for invalid, error
def checkRequest(http_resp, method, abs_path, httpversion, headers, req_body = ""):
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
	method, abs_path, httpversion, headers, req_body = splitRequest(s, recv_msg)

	http_resp = response.copy()
	isReqValid =checkRequest(http_resp, method, abs_path, httpversion, headers, req_body)
	try:
		if isReqValid:
			if method == 'GET':
				resp = GET_Request(http_resp, method, abs_path, httpversion, headers)
			elif method == 'HEAD':
				resp = HEAD_Request(http_resp, method, abs_path, httpversion, headers)
			elif method == 'POST':
				resp = POST_Request(http_resp, method, abs_path, httpversion, headers, req_body)
			elif method == 'PUT':
				resp = PUT_Request(http_resp, method, abs_path, httpversion, headers, req_body)
			elif method == 'DELETE':
				resp = DELETE_Request(http_resp, method, abs_path, httpversion, headers)
		# request is not valid
		else:
			print("Invalid request")
			resp = createResponse(http_resp, method)	# send parameters - make changes to function
	except Exception as e:
		print("Handle request error")
		print(e)
		http_resp['status_code'] = 500
		http_resp['status_msg'] = statusCode.get_status_code(500)
		resp = createResponse(http_resp, method)
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

			response = handleRequest(s, ip, recv_msg)
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
            		break
		except Exception as e:
			print("Error: clientRequests function")
			# add error log
			print(e)
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
			clientSocket, addr = serverSocket.accept()
			client = (clientSocket, addr)
			print('\nNew request received from ', end=""); print(client[1]);
			th = threading.Thread(target = clientRequests, args = (client,))
			th.start()
			client_threads.append(th)
		except KeyboardInterrupt:
			break
		except Exception as e:
			print("\nsome error - main")
			print(e)
			break
			
		# join threads 
		for t in client_threads:
			t.join()
	
	serverSocket.close()
