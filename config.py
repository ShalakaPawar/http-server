from pathlib import Path
import sys
import os, stat

ServerRoot = str(Path().absolute())+'/'

# fetch file location - get, head
FetchFile = 'clientfiles'

#store file location - post, put
StoreFile = 'serverfiles'

# store cookie numbers
CookieDir = ServerRoot + 'cookiefile'
CookieFile = CookieDir + '/cookiefile.txt'
#print(CookieFile)
#print(os.path.exists(CookieFile))

# port number of server
PORT = 2000

# MaxKeepAliveRequests: The maximum number of requests to allow
# during a persistent connection. 
#
# MaxKeepAliveRequests = 50

#
# KeepAliveTimeout: Number of seconds to wait for the next request from the
# same client on the same connection. otherwise close connection
#
KeepAliveTimeout = 5

#
# ErrorLog: The location of the error log file.
#
#ErrorLog ${APACHE_LOG_DIR}/error.log
# store in logfiles folder
ErrorLog = ServerRoot + 'logfiles/errorlog.log'

# contains log of all the requests
AccesLog = ServerRoot + 'logfiles/accesslog.log'

# format
# clientIP date_time request_method response_status resp_message content-length 
"""ErrorLogFormat "[%t] [%l] [pid %P] %F: %E: [client %a] %M"

%a	Client IP address and port of the request
%t	The current time
%l	Loglevel of the message
%P	Process ID of current process
%F	Source file name and line number of the log call
%M	The actual log message
%E	APR/OS error status code and string
"""

#Log level:
#crit		Critical Conditions.	"socket: Failed to get a socket, exiting child"
#error	Error conditions.	"Premature end of script headers"
#info	Informational.	"Server seems busy, (you may need to increase StartServers, or Min/MaxSpareServers)..."
#debug	Debug-level messages	"Opening config file ..."
LogLevel = ['error', 'info', 'debug']



