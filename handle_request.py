from methods import *
from generate_log import *
from functions import *

# SHOULD headers in response
response = {
	'version': 'HTTP/1.1',
	'status_code' : 200,
	'status_msg': 'OK',
	'Date': '',
	'Server': 'Http-Server',			
	'Content-Type':'text/html',
	'Content-Length': 0,
	'Content-Language': 'en'
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
			return method, abs_path, version, headers_dict, req_body

		clength = int(headers_dict.get('Content-Length'))
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


# parse requests
# split request into method, path, version, headers, msg
def handleRequest(s, ip, recv_msg):
	global response
	http_resp = response.copy()
	method, abs_path, httpversion, headers, req_body = splitRequest(http_resp, s, recv_msg)
	
	# get request data handling
	data = None	
	connection = headers.get('Connection', None)
	
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
			ErrorLog(ip, http_resp, method, abs_path, level = 'error')
			resp = createResponse(ip, http_resp, method)	
	except Exception as e:
		ErrorLog(ip, http_resp, method, abs_path, 'error', e)
		resp = createResponse(ip, http_resp, method)
	return resp, data, connection


# keep alive or close
def get_connection(connection):
	if connection is None:
		return False
	if 'keep-alive' in connection:
		return True
	if 'close' in connection:
		return False


def clientRequests(client):
	s = client[0]
	ip = client[1]
	while True:
		try:
			# receive request from client
			recv_msg = s.recv(4096)
			#print(request)
			
			response, data, connection = handleRequest(s, ip[0], recv_msg)
			s.send(response.encode('ISO-8859-1'))
			if data is not None:
				if type(data) == bytes:
					# text files 
					s.send(data)
				else:
					# data is of bytes type
					s.send(data.encode('ISO-8859-1'))
			# check the connection header - if alive or close
			if not get_connection(connection):
				s.close()
				break
		except KeyboardInterrupt:
			print("\nQuitting . . .")
			s.close()
			break
		except ValueError:
			break
		except Exception as e:
			s.close()
			ServerInternalError(500, e)
			break
	return


