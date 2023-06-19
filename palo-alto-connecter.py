import requests
import json
import hashlib

from sys import argv

#_, product, configuration = argv

class device:
	def __init__(
		self,
		login, password,
		web_interface_ip
	):
		self.login = login
		self.password = password
		self.web_interface_ip = web_interface_ip


dev = device(
	login="admin",
	password="admin",
	web_interface_ip="10.1.103.80"
)

def save_response(response, name):
	with open(name, "wb") as f:
		for chunk in response.iter_content(chunk_size=8192):
			f.write(chunk)

with requests.Session() as s:

	auth_response = s.post(
		f"https://{dev.web_interface_ip}/php/login.php",
		data = {
			"prot": "https:",
			"server": dev.web_interface_ip,
			"authType": "init",
			"challengeCookie": "",
			"user": dev.login,
			"passwd": dev.password,
			"challengePws": "",
			"ok": "Log In"
		},
		verify=False
	)

	save_response(auth_response, "auth.html")

	open_response = s.get(
		f"https://{dev.web_interface_ip}/?",
		verify=False
	)
	save_response(open_response, "open.txt")

	string_to_search = "window.Pan.st.st.st"
	st_beginning = open_response.text.find(string_to_search)
	st_beginning = open_response.text.find("\"", st_beginning) + 1
	st_ending = open_response.text.find("\"", st_beginning)

	cookie = open_response.text[st_beginning:st_ending]
	tid = 2

	export_response = s.post(
		f"https://{dev.web_interface_ip}/php/device/export.dynamic_config.php",
		verify=False,
		stream=True
	)

	save_response(export_response, "exported.tgz")

	import_response = s.post(
		f"https://{dev.web_interface_ip}/php/device/config.upload.php",
		data={
			"___tid": str(tid),
			"___token": hashlib.md5((cookie + str(tid)).encode("ascii")).digest().hex(),
			"configType": "dynamic"
		},
		files={
			"file_upload": open("exported.tgz", "rb")
		}
	)

	print(import_response.text)

