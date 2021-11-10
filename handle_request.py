from methods import *
from generate_log import *
from functions import *

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
	# get request data handling
	data = None	
	
	isReqValid =checkRequest(http_resp, method, abs_path, httpversion, headers, req_body)
	try:
		if isReqValid:
			if method == 'GET':
				resp, data = GET_Request(ip, http_resp, method, abs_path, httpversion, headers)
				#print(resp, type(resp))
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
			AccessLog(ip, http_resp, method, abs_path)
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
		ErrorLog(ip, http_resp, method, abs_path, level = 'error', error = '')
		resp = createResponse(ip, http_resp, method)
		# add in error log
	return resp, data



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

			response, data = handleRequest(s, ip[0], recv_msg)
			print("\nResponse:")
			print(response)
			s.send(response.encode('ISO-8859-1'))
			if data:
				try:
					# text files 
					s.send(data.encode('ISO-8859-1'))
				except:
					# data is of bytes type
					s.send(data)

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
			print("\nQuitting . . .")
			break
		except Exception as e:
#			print("Error: clientRequests function")
#			# add error log
#			exc_type, exc_obj, exc_tb = sys.exc_info()
#			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
#			print(exc_type, fname, exc_tb.tb_lineno)
			print(e)
			ServerInternalError(e)
			break
	return


