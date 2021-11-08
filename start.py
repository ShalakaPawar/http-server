import sys, os
import subprocess
# server keeps working in the background

# kill all instances before starting - 
# https://unix.stackexchange.com/questions/50555/kill-many-instances-of-a-running-process-with-one-command
def StartServer():
	try:
		print("Starting server . . ")
		subprocess.Popen(['python3', 'server.py'])
		# ps ax | grep server.py
		print("Server has started")
	except KeyboardInterrupt:
		sys.exit(1)
	except:
		print("Error in starting server")
		sys.exit(1)

if __name__ == '__main__':
	StartServer()
