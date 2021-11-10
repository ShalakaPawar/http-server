from handle_request import *
from functions import *

if __name__ == "__main__":
	serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	serverSocket.bind(('127.0.0.1',config.PORT))
	serverSocket.listen(100)
	print('The server is ready to receive...')

	# list to keep track of client threads
	client_threads = []

	while True:
		try:
			if threading.active_count() > config.MaxRequests:
				print("Server is busy\nRetry after few seconds . . .")
				time.sleep(5)
			clientSocket, addr = serverSocket.accept()
			client = (clientSocket, addr)
			print('\nNew request received from ', end=""); print(client[1]);
			th = threading.Thread(target = clientRequests, args = (client,))
			th.start()
			client_threads.append(th)
		except KeyboardInterrupt:
			print("\nQuitting . . .")
			break
		except Exception as e:
			print("\nserver error")
			ServerInternalError(e)
			break
			
	# join threads 
	for t in client_threads:
		t.join()
	print("Successfully stopped server")
	serverSocket.close()
