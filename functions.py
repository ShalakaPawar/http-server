#!/usr/bin/python
import socket
import threading
import sys
import time
import os
import email.utils
import binascii
import subprocess
import statusCode
import config
from uuid import uuid4

import mimetypes
# global variables
CRLF = '\r\n'


#server will create a cookie 
#create a random number - save in file and necessary info 
#on client request identify if this is 1st access or no

# All HTTP date/time stnps MUST be represented in Greenwich Mean Time (GMT), without exception.
# email.utils.formatdate(timeval=None, localtime=False, usegmt=False)
def date_time_format(local_time = False):
	return email.utils.formatdate(timeval = None, localtime = local_time, usegmt = False)


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


#returns data for response Content-Type header
def get_ctype(filename):
	# extension --> content-type
	#return mimetypes.MimeTypes().guess_type(filename)[0]
	content_types = {
		'html' : 'text/html',	
		'htm' : 'text/html',
		'css' : 'text/css',    
		'csv' : 'text/csv',    
		'html' : 'text/html',    
		'js' : 'text/javascript',    
		'txt' : 'text/plain',    
		'xml' : 'text/xml',    
		'php' : 'text/html',
        	'pdf' : 'application/pdf', 
		'json' : 'application/json',
		'gz' : 'application/gzip',
		'odt' : 'application/vnd.oasis.opendocument.text',
		'ppt' : 'application/vnd.ms-powerpoint',
		'ico': 'image/x-icon',
		'jpg' : 'image/jpeg',	
		'gif' : 'image/gif',   
		'tiff' : 'image/tiff',
		'jpeg' : 'image/jpeg',   
		'webp' : 'image/webp',
		'png' : 'image/png',  
		'mp3': 'audio/mpeg',
        	'wav': 'audio/wav',
		'wma' : 'audio/x-ms-wma',
		'wmv' : 'video/x-ms-wmv',
        	'mpeg': 'video/mpeg',
		'mp4'  : 'video/mp4',
        	'webm': 'video/webm',
		'avi' : 'video/x-msvideo',
        	'3gp': 'video/3gpp'
	}
	extension = filename.split('.')[-1]
	return content_types.get(extension, mimetypes.MimeTypes().guess_type(filename)[0])
		
def isbytesExtension(extension = ''):
	image_ext = ['jpeg', 'jpg', 'png', 'ico', 'gif', 'tiff', 'pdf', 'webp', 'mp3', 'wav', 'wma', 'wmv', 'mpeg', 'mp4', 'avi', '3gp', 'webm']
	if extension in image_ext:
		return True
	return False

def get_method(request):
	request = request.decode('ISO-8859-1')
	method = ((request.split(CRLF))[0]).split(' ')[0]
	return method.strip()
