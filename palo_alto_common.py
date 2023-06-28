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