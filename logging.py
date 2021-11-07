# similar to python logging library


def AccessLog():
	pass

def ErrorLog():
	pass



"""
log_request(code='-', size='-')
Logs an accepted (successful) request. code should specify the numeric HTTP code associated with the response. If a size of the response is available, then it should be passed as the size parameter.

log_error(...)
Logs an error when a request cannot be fulfilled. By default, it passes the message to log_message(), so it takes the same arguments (format and additional values).

log_message(format, ...)
Logs an arbitrary message to sys.stderr. This is typically overridden to create custom error logging mechanisms. The format argument is a standard printf-style format string, where the additional arguments to log_message() are applied as inputs to the formatting. The client ip address and current date and time are prefixed to every message logged.

"""

"""

ErrorLogFormat allows to specify what supplementary information is logged in the error log in addition to the actual log message.
https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat


#Simple example
ErrorLogFormat "[%t] [%l] [pid %P] %F: %E: [client %a] %M"

%a	Client IP address and port of the request
%t	The current time
%l	Loglevel of the message
%P	Process ID of current process
%F	Source file name and line number of the log call
%M	The actual log message
%E	APR/OS error status code and string

example: 

error log
[Thu May 12 08:28:57.652118 2011] [core:error] [pid 8777:tid 4326490112] [client ::1:58619] File does not exist: /usr/local/apache2/htdocs/favicon.ico

access log
127.0.0.1 - - [05/Nov/2021:21:28:40 +0530] "GET /phpmyadmin/js/vendor/tracekit.js?v=4.9.5deb2 HTTP/1.1" 200 11733 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"

[Sat Nov 06 09:20:25.411660 2021] [mpm_prefork:notice] [pid 1185] AH00163: Apache/2.4.41 (Ubuntu) configured -- resuming normal operations

ErrorLogFormat "[%t] [%l] [pid %P] %F: %E: [client %a] %M"
[Fri Feb 01 22:17:49 2019][info] [pid 9] core.c(4739): [client 172.17.0.1:50764] AH00128: File does not exist: /usr/local/apache2/htdocs/favicon.ico

Log level:
crit		Critical Conditions.	"socket: Failed to get a socket, exiting child"
error	Error conditions.	"Premature end of script headers"
info	Informational.	"Server seems busy, (you may need to increase StartServers, or Min/MaxSpareServers)..."
debug	Debug-level messages	"Opening config file ..."



"%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i""

"""
