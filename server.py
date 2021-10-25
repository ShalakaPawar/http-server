#!/usr/bin/python
import socket
import threading
import sys
import time
import os

# global variables
serverIP = '127.0.0.1'
serverPort = 12001
CRLF = '\r\n'


##############################
import statusCode
##############################

# 3 formats
# All HTTP date/time stamps MUST be represented in Greenwich Mean Time (GMT), without exception.
def date_time_stamp():
	pass

def createResponse():
	pass

def GET_Request(request_line, headers_body):
	print("\nGET function called\n")
	print(request_line)
	req_line_split = request_line.split(' ')
	method = req_line_split[0]
	abs_path = req_line_split[1]
	httpversion = req_line_split[2]	
	print(f"Method:{method}\nabs_path: {abs_path}\nversion: {httpversion}")
	"""
	temp = headers_body.split(\r\n\r\n)
	headers = temp[0]
	msgbody = temp[1]	
	"""
	headers_s =  headers_body.split('\n')
	print(f"headers:{headers}\nmsg body:{msgbody}")
	header_field = {}	# store headers in dictionary
	for h in headers_s:
		key, value = h.split(':', 1)
		header_field[key] = value

	# check accept field - error 406 - not acceptable
	# add this condition
	
	curr_path = os.getcwd()
	# storing location
	if abs_path == '/':
		# add index.html 
		p = str(curr_path) + 'index.html'
		


def POST_Request():
	pass

def HEAD_Request():
	pass

def DELETE_Request():
	#A successful response MUST be 200 (OK) if the server response includes a message body, 
	# 202 (Accepted) if the DELETE action has not yet been performed, or 
	#204 (No content) if the DELETE action has been completed but the response does not have a message body.

	pass

def PUT_Request():
	#update an existing resource on the server
	pass


# check for errors in request
def checkRequest():
	pass

# keep alive or close
def connHeader():
	return True

# parse requests
def handleRequest(ip, request):
	print("Handle request function started . . . ")
	# split with CRLF
	req_split = request.split(CRLF)
	for i in req_split:
		print(i)
	print("length=", len(req_split))
	request_line = req_split[0]
	headers_body = req_split[1:]

	# split request line for method, path, http version
	# length will be 3 - get method implementation
	req_line_split = request_line.split(' ')
	method = req_line_split[0]
	abs_path = req_line_split[1]
	httpversion = req_line_split[2]
	print(f"Method:{method}\nabs_path: {abs_path}\nversion: {httpversion}")
	
	if method == 'GET':
		print("call get function")
		GET_Request(request_line, headers_body)
	elif method == 'HEAD':
		print("call head function")
		HEAD_Request()
	elif method == 'POST':
		print("call post function")
		POST_Request()
	elif method == 'PUT':
		print("call put function")
		PUT_Request()
	elif method == 'DELETE':
		print("call delete function")
		DELETE_Request()
	else:
		print("unrecognised method")
		# call status code - which one??
		print(get_status_code(400))
	return


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
			recv_msg = s.recv(1048576)	
			request = recv_msg.decode('ISO-8859-1') # default charset
			#print(recv_msg)
			print(request)
			print("Message received")
			response = handleRequest(ip, request)
			response = "OK bye"
			s.send(response.encode('ISO-8859-1'))
			#s.close()	# for now testing - change
			# check the connection header - if alive or close
			# write a function to check this
			if connHeader() == True:
				# decide what is true
				# close then true
				print("Socket is closing . . .")
				s.close()
				break
		except:
			print("Error: clientRequests function")
			break
	return

if __name__ == "__main__":
	serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	serverSocket.bind(('',serverPort))
	serverSocket.listen(100)
	print('The server is ready to receive...')

	# list to keep track of client threads
	client_threads = []

	while True:
		try:
			clientSocket, addr = serverSocket.accept()
			client = (clientSocket, addr)
			print('\nNew request received from ', end=""); print(client);
			th = threading.Thread(target = clientRequests, args = (client,))
			th.start()
			client_threads.append(th)		
		except:
			print("\nsome error - main")
			break
			
		# join threads 
		for t in client_threads:
			t.join()
	
	serverSocket.close()
