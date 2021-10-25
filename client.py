#!/usr/bin/python
from socket import *
from threading import Thread
import sys
import time

serverName = '127.0.0.1'
serverPort = 12001

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName,serverPort))

request_msg = '''GET /hello.html HTTP/1.1\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT) Host: www.tutorialspoint.com Accept-Language: en-us Accept-Encoding: gzip, deflate Connection: Keep-Alive\r\n\r\n'''


"""
sendThread = Thread(target=sendMsg)
sendThread.daemon = True
sendThread.start()

receiveThread = Thread(target=receiveMsg)
receiveThread.daemon = True
receiveThread.start()

receiveThread.join()
sendThread.join()
"""
myMsg = request_msg
clientSocket.send(myMsg.encode('ISO-8859-1'))

m = clientSocket.recv(1048).decode('ISO-8859-1')
print(m)
clientSocket.close()

