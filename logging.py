# similar to python logging library

"""
log_request(code='-', size='-')
Logs an accepted (successful) request. code should specify the numeric HTTP code associated with the response. If a size of the response is available, then it should be passed as the size parameter.

log_error(...)
Logs an error when a request cannot be fulfilled. By default, it passes the message to log_message(), so it takes the same arguments (format and additional values).

log_message(format, ...)
Logs an arbitrary message to sys.stderr. This is typically overridden to create custom error logging mechanisms. The format argument is a standard printf-style format string, where the additional arguments to log_message() are applied as inputs to the formatting. The client ip address and current date and time are prefixed to every message logged.

"""
