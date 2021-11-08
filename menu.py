import os
import sys
import subprocess


def RestartServer():
	try:
		StopServer()
		StartServer()
	except KeyboardInterrupt:
		sys.exit(1)
	except:
		print("Error in restarting the server")

if __name__ == '__main__':
	# choose start stop restart
	# menu
	arg = len(sys.argv)
	print("1. start server\n2. stop server\n3. restart server")
	

