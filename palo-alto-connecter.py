import requests
import json

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


dev = device("admin", "ADMIN", "10.1.103.80")

def save_response(response, name):
	with open(name, "wb") as f:
		for chunk in response.iter_content(chunk_size=8192):
			f.write(chunk)

s = requests.Session()

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

print(auth_response.cookies)

save_response(auth_response, "auth.html")

export_response = s.post(
	f"https://{dev.web_interface_ip}/php/device/export.dynamic_config.php",
	verify=False,
	stream=True
)

print(export_response.headers)
save_response(export_response, "export.html")