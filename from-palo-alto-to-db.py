from palo_alto_common import *


# objects

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

for e in pan_fetch_addresses():
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

security_rules_ids = []
position = 0

for e in pan_fetch_security_rules():
	position += 1
	name = e["@name"]

	if e["application"]["member"] != "any":
		raise RuntimeError("applications aren't supported yet")

	if e["service"]["member"] != "any":
		raise RuntimeError("services aren't supported yet")

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
		"protocol": object_id_by_name[e["service"]["member"]],
		"application": object_id_by_name[e["application"]["member"]],
		"action": {
			"deny": "REJECT",
			"allow": "ACCEPT",
			"drop": "DROP"
			# TODO "reset-client", "reset-server", "reset-both"?
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

nat_rules_ids = []
position = 0

for e in pan_fetch_nat_rules():
	position += 1
	name = e["@name"]

	# check if "from" and "to" zones set to "any"
	if e["from"]["member"][0] != "any" or e["to"]["member"][0] != "any":
		print("NAT zones aren't supported by FWMT")

	params = {
		"product": product_id,
		"position": position,
		"name": name,
		"description": e["description"] if "description" in e else "",
		# TODO "orignal" - typo in FWMT
		"orignal_src_ip": object_id_by_name[e["source"]["member"][0]],
		"original_dst_ip": object_id_by_name[e["destination"]["member"][0]],
		"original_port": ""
	}

	source_translation_type = list(e["source-translation"].keys())[0]
	source_translation = e["source-translation"][source_translation_type]
	translated_object_type = list(source_translation.keys())[0]
	translated_object = source_translation[translated_object_type]

	def translated_addresses():
		translated_addresses = translated_object["member"]
		translated_addresses_count = len(translated_addresses)
		if translated_addresses_count > 1: raise RuntimeError(
			f"FWMT doesn't support multiple \
			({translated_addresses_count}) translation addresses"
		)
		address_name = translated_addresses[0]
		params["translated_src_ip"] = object_id_by_name[address_name]

	match source_translation_type:
		case "dynamic-ip-and-port":
			match translated_object_type:
				case "interface-address":
					raise RuntimeError(
						"interface source translation is not supported yet"
					)
				case "translated-address":
					translated_addresses()
		case "dynamic-ip":
			match translated_object_type:
				case "translated-address":
					translated_addresses()
				case "fallback":
					raise RuntimeError("isn't supported")
		case "static-ip":
			params["translated_src_ip"] = translated_object[
				"translated-address"
			]
			if "bi-directional" in translated_object:
				raise RuntimeError("don't know what to do with it yet xD")
		case _:
			raise RuntimeError(
				f"no source translation for nat rule named \"{name}\""
			)

	# "Only one of
	#  *destination-translation* or
	#  *dynamic-destination-translation* must be presented."
	if "destination-translation" in e:
		params["translated_dst_ip"] \
			= e["destination-translation"]["translated-address"]
		params["translated_dst_port"] \
			= e["destination-translation"]["translated-port"]
	elif "dynamic-destination-translation" in e:
		raise RuntimeError("dont' understand it yed :|")

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