import sys, os
import subprocess
# server keeps working in the background


#You can find the process and its process Id with this command:
#ps ax | grep test.py
##ps ax | grep filename.py
## python -u filename.py > FileToFlush &

#It is also possible to kill the process by using pkill, but make sure you check if there is not a different script running with the same name:
#pkill -f test.py

def StopServer():
	try:
		print("Closing Server . . .")
		subprocess.Popen.terminate()
		print("Server has been closed")
	except KeyboardInterrupt:
		sys.exit(1)
	except:
		print("Error in closing server")
		sys.exit(1)

if __name__ == '__main__':
	StopServer()
