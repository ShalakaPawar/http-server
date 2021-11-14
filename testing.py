import requests
import sys
from prettytable import PrettyTable

PORT = 2000
URL = 'http://127.0.0.1:{}/'.format(PORT)

# print the response request headers, result, data - test case pass/fail
def printOutput(method, response, isPass = False):
	table = PrettyTable()
	table.field_names = ["Field", "Value"]
	table.add_row(['Method', method])
	table.add_row(["Response", str(response.status_code) +' '+ response.reason])
	if isPass:
		table.add_row(["Test case", "Successful"])
	else:
		table.add_row('[Test case]', "Fail")
	print(table)
	return
	
	

def test_GET():
	get_files = {'index.html', 'sample.html', 'audio.mp3', 'Schema.jpg', '200w.webp'}
	for mfile in get_files:
		try:
			response = requests.get(URL + mfile)
			print(f"\nTesting GET - {mfile.split('.')[-1]}")
			printOutput('GET', response, True)
			#print(f"GET Request Successful\nStatus code: {response.status_code}")
		except Exception as e:
			#print("Error Occured (GET)")
			printOutput('GET', response, False)
	
	# test for headers
	# test for Accept header
	try:
		print("\nTesting Accept header:")
		response = requests.get(URL + 'sample.html', headers={'Accept': 'image/png, audio/wav'})
		if response.status_code == 406:
			printOutput('GET', response, True)
			#print(f"Accept Header Test Successful\nStatus code: {response.status_code}")
	except Exception as e:
		#print("Error Occured (GET Accept header)")
		printOutput('GET', response, False)
	
	
	# test for If-Match, If-Modified-Since header
	try:
		print("\nTesting Conditional header:\nMake a GET request for file sample.html")
		response = requests.get(URL + 'sample.html')
		print("GET request successful")
		print("Fetch file again with If-Match header")
		response = requests.get(URL + 'sample.html', headers={'If-Match': '{}'.format(response.headers.get('ETag', None))})
		if response.status_code == 304:
			printOutput('GET', response, True)
			#print(f"Conditional Header Test Successful\nStatus code: {response.status_code}")
	except Exception as e:
		#print("Error Occured (GET Conditional header)")
		printOutput('GET', response, False)


def test_HEAD():
	get_files = {'index.html', 'sample.html', 'audio.mp3', 'Schema.jpg', '200w.webp'}
	for mfile in get_files:
		try:
			print(f"\nTesting HEAD - {mfile.split('.')[-1]}")
			response = requests.head(URL + mfile)
			printOutput('HEAD', response, True)
			#print(f"HEAD Request Successful\nStatus code: {response.status_code}")
		except Exception as e:
			#print("Error Occured (HEAD)")
			printOutput('HEAD', response, True)


def test_PUT():
	put_path = URL + '/serverfiles/put.txt'
	formdata = {"Name": "Shalaka Pawar", "Email": "shalaka@gmail.com", "College": "COEP"}
	try:
		print("\nTesting PUT - Form Data:")
		response = requests.put(put_path, data=formdata)
		printOutput('PUT', response, True)
		#print(f"PUT Request Successful\nStatus code: {response.status_code}")
	except Exception as e:
		#print("Error Occured (PUT):")
		printOutput('PUT', response, True)

def test_POST():
	post_path = URL 
	formdata = {"Name": "Shalaka Pawar", "Email": "shalaka@gmail.com", "College": "COEP"}
	mfiles = {'file': open('clientfiles/test.py' ,'rb')}
	try:
		print("\nTesting POST - Form Data:")
		response = requests.post(post_path, data=formdata)
		printOutput('POST', response, True)
		#print(f"POST Request Successful\nStatus code: {response.status_code}")
	except Exception as e:
		#print("Error Occured (POST):")
		printOutput('POST', response, False)

	try:
		print("\nTesting POST - Uploaded File:")
		response = requests.post(post_path, files = mfiles)
		printOutput('POST', response, True)
		#print(f"POST Request Successful\nStatus code: {response.status_code}")
	except Exception as e:
		#print("Error Occured (POST):")
		printOutput('POST', response, False)
	

def test_DELETE():		
	delete_path1 = URL + "a.png"	#a,b,c
	delete_path2 = URL + "deleteme.txt"
	delete_path3 = URL + "deleteme2.txt"
	try:
		print("\nTesting DELETE:")
		response = requests.delete(delete_path1)
		printOutput('DELETE', response, True)
		#print(f"Deleted Request Successful\nStatus code: {response.status_code}")
	except Exception as e:
		#print('Error Occurred (DELETE):')
		printOutput('DELETE', response, False)

	try:
		print("\nTesting DELETE:")
		response = requests.delete(delete_path2)
		printOutput('DELETE', response, True)
		#print(f"Deleted Request Successful\nStatus code: {response.status_code}")
	except Exception as e:
		#print('Error Occurred (DELETE):')
		printOutput('DELETE', response, False)

if __name__=='__main__':
	try:
		test_GET()
		test_HEAD()
		test_PUT()
		test_POST()
		test_DELETE()
	except:
		print("Start the server first!!")

