
from functions import *
import datetime

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

# response type header
# Last-Modified: <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT
def LastModified(filepath):
	weekdays = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
	months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" ]
	try:
		modified = os.path.getmtime(filepath)
	except:
		modified = 0	# 404 not found - caught
	year,month,day,hour,minute,second, weekday=time.gmtime(modified)[:-2]
	#print(time.gmtime(modified))
	lm = "%s, %02d %s %d %02d:%02d:%02d"%(weekdays[weekday], day, months[month-1], year, hour, minute, second) + ' GMT'
	return lm.strip()

#print(LastModified('clientfiles/audio.mp3'))

# add required parameters
# need method for POST, PUT
def createResponse(ip, http_resp, method, cType= 'text/html', cLength = 0):
	#response['statusCode'] = statusCode			# already added outside
	#response['statusResp'] = statusCode.get_status_code(statusCode)
	http_resp['Date'] = str(date_time_format(False))
	http_resp['Content-Type'] = cType
	http_resp['Content-Length'] = cLength
	#http_resp['ETag'] = '123456'
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

