import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import sys

fwmt_address = "http://127.0.0.1:8000/"

product_name, configuration_name = (
	sys.argv[1], # "Super-Puper FW"
	sys.argv[2]  # "SomeConfiguration"
)

product_response = requests.get(
	f"{fwmt_address}/product/{product_name}"
)
if product_response.text == "Error":
	raise RuntimeError(f"couldn't fetch product by name \"{product_name}\"")

product = json.loads(product_response.text)[0]
product_id = product["id"]

pan_ip = product["host_ip"]
pan_port = product["host_port"]
pan_address = pan_ip + (pan_port if pan_port != None else "")
pan_version = product["version"]
pan_key = product["uid"]

pan_headers = { "X-PAN-KEY": pan_key }
pan_params = {
	"location": "vsys",
	"vsys": "vsys1"
}


def pan_fetch_addresses():
	print("fetching addresses from PAN... ", end = "")
	response = requests.get(
		f"{pan_address}/restapi/{pan_version}/Objects/Addresses",
		verify = False,
		headers = pan_headers,
		params = pan_params
	)
	if response.status_code != 200: raise RuntimeError(
		"couldn't fetch addresses"
	)
	print("success")
	return json.loads(response.text)["result"]["entry"]

def pan_fetch_security_rules():
	print("fetching security rules from PAN... ", end = "")
	response = requests.get(
		f"{pan_address}/restapi/{pan_version}/Policies/SecurityRules",
		verify = False,
		headers = pan_headers,
		params = pan_params
	)
	if response.status_code != 200: raise RuntimeError(
		"couldn't fetch security rules"
	)
	print("success")
	return json.loads(response.text)["result"]["entry"]

def pan_fetch_nat_rules():
	print("fetching NAT rules from PAN... ", end = "")
	response = requests.get(
		f"{pan_address}/restapi/{pan_version}/Policies/NatRules",
		verify = False,
		headers = pan_headers,
		params = pan_params
	)
	if response.status_code != 200: raise RuntimeError(
		"couldn't fetch NAT rules"
	)
	print("success")
	return json.loads(response.text)["result"]["entry"]