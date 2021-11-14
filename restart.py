import sys
import os
import signal

from stop import StopServer
from start import StartServer

if __name__ == '__main__':
	StopServer()
	StartServer()
