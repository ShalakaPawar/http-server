#!/usr/bin/python
import socket
import threading
import sys
import time
import os
import email.utils
import config
# global variables
serverIP = '127.0.0.1'
serverPort = 12001
CRLF = '\r\n'

os.system("python3 config.py")

##############################
import statusCode
##############################


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

# add required parameters
# need method for POST, PUT
def createResponse(http_resp, method, cType= 'text/html',cEncoding= 'gzip', cLength = 0):
	#response['statusCode'] = statusCode			# already added outside
	#response['statusResp'] = statusCode.get_status_code(statusCode)
	http_resp['Date'] = str(date_time_format(False))
	http_resp['Content-Encoding'] = cEncoding
	http_resp['Content-Type'] = cType
	http_resp['Content-Length']=cLength
	http_response = ""
	first_line = ''
	for key, value in http_resp.items():
		if key in ['version', 'status_code', 'status_msg']:
			first_line +=str(value) + ' '
		else:
			http_response += CRLF
			http_response += str(key) + ": " + str(value)
		
	http_response += CRLF + CRLF
	http_response = first_line + http_response
	print("http-response =\n", http_response)
	return http_response

# returns method, abs_path, httpversion, headers, msg
def splitRequest(request):
	r =  request.split(CRLF)
	req_line = r[0]
	headers = r[1: ]	# till the CRLF is identified
	msg = r[-1]	# for post put

	first_line = req_line.split(' ')
	method, abs_path, version = first_line
	headers_dict = {}
	for i in headers:
		try:
			hfield, hvalue = i.split(':', 1)	
			headers_dict[hfield] = hvalue
		except:
			continue
	return method, abs_path, version, headers_dict, msg
	

def GET_Request(http_resp, method, abs_path, httpversion, headers, msg=""):
	print("\nGET function called\n")
	print(f"Method:{method}\nabs_path: {abs_path}\nversion: {httpversion}\nheaders:{headers},\n msg :{msg}")
	
	
		


def POST_Request(http_resp, method, abs_path, httpversion, headers, msg=''):
	pass

def HEAD_Request(http_resp, method, abs_path, httpversion, headers, msg=''):
	pass

def DELETE_Request(http_resp, method, abs_path, httpversion, headers, msg=''):
	#A successful response MUST be 200 (OK) if the server response includes a message body, 
	# 202 (Accepted) if the DELETE action has not yet been performed, or 
	#204 (No content) if the DELETE action has been completed but the response does not have a message body.

	pass

def PUT_Request(http_resp, method, abs_path, httpversion, headers, msg=''):
	#update an existing resource on the server
	pass


# check for errors in request
# msg_body is for post put
# return True is request is valid 
# False for invalid, error
def checkRequest(http_resp, method, abs_path, httpversion, headers, msg_body = ""):

	if method not  in ["GET", "POST", "PUT", "DELETE", "HEAD"]:
		http_resp['status_code'] = 501
		http_resp['status_msg'] = statusCode.get_status_code(501)
		return False

# keep alive or close
def connHeader():
	return True


# parse requests
# split request into method, path, version, headers, msg
def handleRequest(ip, request):
	global response
	print("Handle request function started . . . ")
	method, abs_path, httpversion, headers, msg = splitRequest(request)
	http_resp = response.copy()
	isReqValid =checkRequest(http_resp, method, abs_path, httpversion, headers, msg)
	try:
		if isReqValid:
			print(f"Method:{method}")
		
			if method == 'GET':
				print("call get function")
				GET_Request(http_resp, method, abs_path, httpversion, headers, msg)
			elif method == 'HEAD':
				print("call head function")
				HEAD_Request(http_resp, method, abs_path, httpversion, headers, msg)
			elif method == 'POST':
				print("call post function")
				POST_Request(http_resp, method, abs_path, httpversion, headers, msg)
			elif method == 'PUT':
				print("call put function")
				PUT_Request(http_resp, method, abs_path, httpversion, headers, msg)
			elif method == 'DELETE':
				print("call delete function")
				DELETE_Request(http_resp, method, abs_path, httpversion, headers, msg)
		# request is not valid
		else:
			print("Invalid request")
			resp = createResponse(http_resp, method)	# send parameters - make changes to function
			return resp
			

	except Exception as e:
		print(e)
		http_resp['status_code'] = 500
		http_resp['status_msg'] = statusCode.get_status_code(500)
		resp = createResponse(http_resp, method)
		# add in error log
	return resp


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
			request = recv_msg.decode('ISO-8859-1') # default charset
			print(request)

			response = handleRequest(ip, request)
			
			#response_body = b"""<html><body><h1>Request received!</h1><body></html>"""
			#response_line = b"HTTP/1.1 200 OK\r\n"

			#headers = b"".join([b"Server: Crude Server\r\n", b"Content-Type: text/html\r\n"])
			#blank_line = b"\r\n"

			#response_body = b"""<html>
			#	<body>
			#	<h1>Request received!</h1>
			#	<body>
			#	</html>
			#"""
			#response = b"".join([response_line, headers, blank_line, response_body])
			
			s.send(response.encode())

			#s.close()	# for now testing - change
			# check the connection header - if alive or close
			# write a function to check this
			if connHeader() == True:
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
