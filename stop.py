import sys
import os
import signal

def StopServer():
	try:
		print("Closing Server . . .")
		# kills all running processes
		for process in os.popen(f"ps ax | grep httpserver.py | grep -v grep"):
            		pid = process.split()[0]
            		os.kill(int(pid), signal.SIGKILL)
		print("Server has been closed")
	except KeyboardInterrupt:
		sys.exit(1)
	except:
		print("Error in closing server")
		sys.exit(1)

if __name__ == '__main__':
	StopServer()
