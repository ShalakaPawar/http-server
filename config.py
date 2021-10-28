from pathlib import Path
import sys
import os

ServerRoot = str(Path().absolute())

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
ErrorLog = ServerRoot + '/logfiles/errorlog.log'

# contains log of all the requests
AccesLog = ServerRoot + '/logfiles/accesslog.log'

# format
# clientIP date_time request_method response_status resp_message content-length 




