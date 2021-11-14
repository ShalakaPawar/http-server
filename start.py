import sys
import os
# server keeps working in the background

def StartServer():
	try:
		print("Starting server . . ")
		os.system("python3 httpserver.py &")
		print("Server has started")
	except KeyboardInterrupt:
		sys.exit(1)
	except:
		print("Error in starting server")
		sys.exit(1)

if __name__ == '__main__':
	StartServer()
