from palo_alto_common import *


# objects

print("fetching objects from PAN... ", end = "")
response = requests.get(
	f"{pan_address}/restapi/{pan_version}/Objects/Addresses",
	verify = False,
	headers = pan_headers,
	params = pan_params
)
if response.status_code != 200: raise RuntimeError("couldn't fetch objects")
print("success")

# maps object ID in DB to object name if FW
object_id_by_name = dict()
objects_ids = []

def add_object(fw_name, db_id):
	object_id_by_name[fw_name] = db_id
	objects_ids.append(db_id)

def add_any_object():
	any_object_response = requests.get(f"{fwmt_address}/object/Any")
	if any_object_response.text == "Error": raise RuntimeError(
		"\"Any\" object is not defined in DB?"
	)
	any_object = json.loads(any_object_response.text)[0]
	add_object("any", int(any_object["id"]))

print("fetching \"Any\" object from DB... ", end = "")
add_any_object()
print("success")

for e in json.loads(response.text)["result"]["entry"]:
	name = e["@name"]

	params = {
		"name": name,
		"product": product_id
	}

	def try_add(type_name):
		if type_name not in e: return False
		params["object_type"] = type_name
		params["object_value"] = e[type_name]
		return True

	if (
		not try_add("ip-netmask") and
		not try_add("ip-range") and
		not try_add("ip-wildcard")
	): raise RuntimeError(f"couldn't add object named \"{name}\"")

	print(f"adding object named \"{name}\" to DB... ", end = "")
	response = requests.post(
		f"{fwmt_address}/object/add",
		json = params
	)
	if response.text == "Error": raise RuntimeError(
		f"couldn't add object named \"{name}\""
	)
	print("success")

	id = int(response.text)
	add_object(name, id)

# security rules

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

	print(f"adding security rule named \"{name}\" to DB... ", end = "")
	response = requests.post(
		f"{fwmt_address}/sec_rule/add",
		json = params
	)
	if response.text == "Error": raise RuntimeError(
		f"couldn't add security rule named \"{name}\""
	)
	print("success")

	security_rules_ids.append(int(response.text))


# NAT rules

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
		"orignal_src_ip": object_id_by_name[e["source"]["member"][0]],
		"original_dst_ip": object_id_by_name[e["destination"]["member"][0]],
		"original_port": "",
		"translated_src_ip": object_id_by_name[e["source"]["member"][0]],
		"translated_dst_ip": object_id_by_name[e["destination"]["member"][0]],
		"translated_dst_port": "",
	}

	print(f"adding NAT rule named \"{name}\" to DB... ", end = "")
	response = requests.post(
		f"{fwmt_address}/nat_rule/add",
		json = params
	)
	if response.text == "Error": raise RuntimeError(
		f"couldn't add nat rule named \"{name}\""
	)
	print("success")

	nat_rules_ids.append(int(response.text))


# configuration

print(
	f"adding configuration named \"{configuration_name}\" to DB... ", end = ""
)
response = requests.post(
	f"{fwmt_address}/config/add",
	json = {
		"name": configuration_name,
		"product": product_id,
		"security_rules": security_rules_ids,
		"nat_rules": nat_rules_ids,
		"fw_objects": objects_ids
	}
)
if response.text == "Error": raise RuntimeError(
	f"couldn't add configuration named \"{configuration_name}\""
)
print("success")