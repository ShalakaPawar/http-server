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

# port number of server
PORT = 2000

# MaxKeepAliveRequests: The maximum number of requests to allow
# during a persistent connection.
MaxRequests = 30

# KeepAliveTimeout: Number of seconds to wait for the next request from the
# same client on the same connection. otherwise close connection
KeepAliveTimeout = 5


LogFolder = ServerRoot + 'logfiles'
# ErrorLog: The location of the error log file.
# ErrorLogFormat "[current time] [client IP] [log level] [pid PID] [request status line] [response status code, msg] [error message]"
ErrorLog = LogFolder + '/errorlog.txt'

# contains log of all the requests
AccessLog = LogFolder + '/accesslog.txt'

#Log level:
#crit		Critical Conditions.	"socket: Failed to get a socket, exiting child"
#error	Error conditions.	"Premature end of script headers"
#info	Informational.	"Server seems busy."
#debug	Debug-level messages	"Opening config file ..."
LogLevel = ['error', 'info', 'debug']



