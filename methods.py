from functions import *
from response import *
from generate_log import *

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
	isplain = True
	try:
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
				ErrorLog(ip, http_resp, method, abs_path, 'error')
			else:	
				# check if given files are images/audio - read binary
				if isbytesExtension(filename.split('.')[-1]):
					isplain = False
					filedata = b''
					with open(p, 'rb') as f:
						for line in f:
							try:
								filedata += line
							except:
								pass
				else:
					with open(p, 'rb') as f:
						for bline in f:
							try:
								line = bline.decode('utf-8')
								filedata += line
							except UnicodeDecodeError as ex:
								pass
					
	except Exception as e:
		print("GET request error")
#		exc_type, exc_obj, exc_tb = sys.exc_info()
#		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
#		print(exc_type, fname, exc_tb.tb_lineno)
		InternalServerError(e)
		print(e)
	
	if not isplain:
		resp = createResponse(ip, http_resp, method, get_ctype(filename), os.path.getsize(p))
	resp = createResponse(ip, http_resp, method, get_ctype(filename), len(filedata))
	AccessLog(ip, http_resp, method, abs_path)
	return resp, filedata


def HEAD_Request(ip, http_resp, method, abs_path, httpversion, headers):
	fileExtension = ''	
	file_path = ''
	filedata = ''
	isplain = True
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
			ErrorLog(ip, http_resp, method, abs_path, 'error')
		else:
			try:
				# check if given files are images/audio - read binary
				if isbytesExtension(filename.split('.')[-1]):
					isplain = False
					filedata = b''
					with open(p, 'rb') as f:
						for line in f:
							try:
								filedata += line
							except:
								pass
				else:
					with open(p, 'r') as f:
						for line in f:
							filedata += line

			except Exception as e:
				print("Head request error")
				http_resp['status_code'] = 500
				http_resp['status_msg'] = statusCode.get_status_code(500)
				ServerError(e)
				filedata = ''
	
	AccessLog(ip, http_resp, method, abs_path)
	if not isplain:
		resp = createResponse(ip, http_resp, method, get_ctype(filename), os.path.getsize(p))
		return resp
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
		print("Post requests error")
#		exc_type, exc_obj, exc_tb = sys.exc_info()
#		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
#		print(exc_type, fname, exc_tb.tb_lineno)
		ErrorLog(ip, http_resp, method, abs_path, 'error', e)
		print(e)
	# data fetched successfully
#	print("File content =",filedata)
#	for k, v in formData.items():
#		print(f'{k}={v}')

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
			ErrorLog(ip, http_resp, method, abs_path, 'error')
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
		ErrorLog(ip, http_resp, method, abs_path, 'error', e)
		print(e)

	post_response = '<html><h2>POST Request Successful!!!</h2></html>'
	resp = createResponse(ip, http_resp, method, 'text/html', len(post_response)) + post_response
	AccessLog(ip, http_resp, method, abs_path)
	return resp

def PUT_Request(ip, http_resp, method, abs_path, httpversion, headers, req_body = b''):
	#update an existing resource on the server
	path = config.ServerRoot

	if abs_path == '/':
		p = path + 'put.txt'
	else:
		p = path + abs_path[1:]
		flag = False
		l = abs_path.split('/')
		for i in l[1:]:
			if '.' in i:
				flag = True
				break
			path += i
			if not os.path.exists(path):
				os.mkdir(path)
		if not flag:
			p += 'put.txt'
	#creates file if does not exist	
	with open(p, 'w') as mfile:
		pass
	if not os.access(p, os.W_OK):
		http_resp['status_code'] = 403
		http_resp['status_msg'] = statusCode.get_status_code(403)
		ErrorLog(ip, http_resp, method, abs_path, 'error')
		return createResponse(ip, http_resp, method)
	
	with open(p, 'w') as mfile:
		mfile.write('\n')
		mfile.write(str(req_body))
	put_response = '<html><h2>PUT Request Successful!!!</h2></html>'
	resp = createResponse(ip, http_resp, method, 'text/html', len(put_response)) + put_response
	AccessLog(ip, http_resp, method, abs_path)
	return resp


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
				

