import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json

management_address = "https://10.1.103.80"
pan_os_version = "9.0"
api_key = "LUFRPT1WS0FqaDliZC9qUHRqdzRkYmh6SjhBUXVRTFk9M0NCZkhWTFhSK3lmaTk4SEc3bXE0WTVzVkF4cVh2dFdQMlg4S2ZVdkZFYz0="
fwmt_address = "http://127.0.0.1:8000/"
product_id = 1

# objects

response = requests.get(
	f"{management_address}/restapi/{pan_os_version}/Objects/Addresses",
	verify=False,
	headers = { "X-PAN-KEY": api_key },
	params = {
		"location": "vsys",
		"vsys": "vsys1"
	}
)
if response.status_code != 200: raise RuntimeError("couldn't query objects")

object_id_by_name = dict()

any_object_response = requests.get(f"{fwmt_address}/object/any")
if any_object_response.text == "Error":
	raise RuntimeError("any object is not defined in DB?")

object_id_by_name["any"] = int(json.loads(any_object_response.text)[0]["id"])

for e in json.loads(response.text)["result"]["entry"]:
	name = e["@name"]

	params = {
		"name": name,
		"product": product_id
	}

	def try_add(name):
		if name not in e: return False
		params["object_type"] = name
		params["object_value"]  = e[name]
		return True

	if (
		not try_add("ip-netmask") and
		not try_add("ip-range") and
		not try_add("ip-wildcard")
	): raise RuntimeError(f"couldn't add object named \"{name}\"")

	result = requests.post(
		f"{fwmt_address}/object/add",
		json = params
	)
	if result.text == "Error":
		raise RuntimeError(f"couldn't add object named \"{name}\"")

	object_id = int(result.text)
	object_id_by_name[name] = object_id

# security rules

response = requests.get(
	f"{management_address}/restapi/{pan_os_version}/Policies/SecurityRules",
	verify=False,
	headers = { "X-PAN-KEY": api_key },
	params = {
		"location": "vsys",
		"vsys": "vsys1"
	}
)

if response.status_code != 200:
	raise RuntimeError("couldn't query security rules")

security_rules_ids = []
position = 0

for e in json.loads(response.text)["result"]["entry"]:
	position += 1
	name = e["@name"]
	params = {
		"product": product_id,
		"position": position,
		#"policy": ?
		"name": name,
		"description": e["descripion"] if "description" in e else "",
		"zone_in": e["from"]["member"][0],
		"zone_out": e["to"]["member"][0],
		"source": [
			object_id_by_name[member_name]
			for member_name in e["source"]["member"]
		],
		"destination": [
			object_id_by_name[member_name]
			for member_name in e["destination"]["member"]
		],
		# "dst_port": [], # ?
		# "protocol": ?
		# "application": [], # ?
		"action": {
			"deny": "REJECT",
			"allow": "ACCEPT",
			"drop": "DROP"
		} [e["action"]],
		"logging":
			("log-start" in e and e["log-start"] == "yes") or
			("log-end"   in e and e["log-end"]   == "yes"),
		"feature1": e["log-start"] if "log-start" in e else "",
		"feature2": e["log-end"] if "log-end" in e else "",
		"feature3": e["log-setting"] if "log-setting" in e else "",
	}

	result = requests.post(
		f"{fwmt_address}/sec_rule/add",
		json = params
	)
	if result.text == "Error":
		raise RuntimeError(f"couldn't add security rule named \"{name}\"")

	security_rules_ids.append(int(result.text))


# NAT rules

response = requests.get(
	f"{management_address}/restapi/{pan_os_version}/Policies/NatRules",
	verify=False,
	headers = { "X-PAN-KEY": api_key },
	params = {
		"location": "vsys",
		"vsys": "vsys1"
	}
)

if response.status_code != 200: raise RuntimeError("couldn't query nat rules")

nat_rules_ids = []
position = 0

for e in json.loads(response.text)["result"]["entry"]:
	position += 1
	name = e["@name"]
	params = {
		"product": product_id,
		"position": position,
		"name": name,
		"description": e["description"] if "description" in e else "",
		"original_src_ip": object_id_by_name[e["source"]["member"][0]],
		"original_dst_ip": object_id_by_name[e["destination"]["member"][0]],
		"original_port": "",
		"translated_src_ip": object_id_by_name[e["source"]["member"][0]],
		"translated_dst_ip": object_id_by_name[e["destination"]["member"][0]],
		"translated_dst_port": "",
	}

	result = requests.post(
		f"{fwmt_address}/nat_rule/add",
		json = params
	)
	if(result.text == "Error"):
		raise RuntimeError(f"couldn't add nat rule named \"{name}\"")

	nat_rules_ids.append(int(result.text))
