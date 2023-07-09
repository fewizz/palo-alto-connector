from palo_alto_common import *

# objects

# maps object ID in DB to object name if FW
object_db_id_by_fw_name = dict()
objects_db_ids = []

def add_object_to_the_dict(fw_name, db_id):
	object_db_id_by_fw_name[fw_name] = db_id
	objects_db_ids.append(db_id)

def fetch_and_add_any_object_to_the_dict():
	any_object_response = requests.get(f"{fwmt_address}/object/Any")
	jsn = json.loads(any_object_response.text)
	if any_object_response.text == "Error" or len(jsn) == 0: raise RuntimeError(
		"\"Any\" object is not defined in a DB?"
	)
	any_object = jsn[0]
	add_object_to_the_dict("any", int(any_object["id"]))

print("fetching \"Any\" object from DB... ", end = "")
fetch_and_add_any_object_to_the_dict()
print("success")

def add_object_to_the_db(name, type, value):
	print(f"adding object named \"{name}\" to the DB... ", end = "")
	response = requests.post(
		f"{fwmt_address}/object/add",
		json = {
			"name": name,
			"product": product_id,
			"object_type": type,
			"object_value": value
		}
	)
	if response.text == "Error": raise RuntimeError(
		f"couldn't add object named \"{name}\""
	)
	print("success")
	id = int(response.text)
	add_object_to_the_dict(name, id)

for e in pan_fetch_addresses():
	name = e["@name"]

	def try_add(type_name):
		if type_name not in e: return False
		add_object_to_the_db(
			name = name,
			type = type_name,
			value = e[type_name]
		)
		return True

	if (
		not try_add("ip-netmask") and
		not try_add("ip-range") and
		not try_add("ip-wildcard")
	): raise RuntimeError(f"couldn't add object named \"{name}\"")

# security rules

def possibly_add_and_get_object_db_id_by_name(name, type, value):
	if name not in object_db_id_by_fw_name:
		add_object_to_the_db(name, type, value)
	return object_db_id_by_fw_name[name]

def possibly_add_and_get_application_db_id_by_name(app_name):
	return possibly_add_and_get_object_db_id_by_name(
		name = app_name,
		type = "application",
		value = "Wroom Wroom"
	)

def possibly_add_and_get_zone_db_id_by_name(zone_name):
	return possibly_add_and_get_object_db_id_by_name(
		name = zone_name,
		type = "zone",
		value = ""
	)

security_rules_ids = []

for e in pan_fetch_security_rules():
	position = len(security_rules_ids) + 1
	name = e["@name"]

	services = e["service"]["member"]
	services_count = len(services)
	if services_count > 1: raise RuntimeError(
		f"multiple services ({services_count}) aren't supported yet"
	)

	params = {
		"product": product_id,
		"position": position,
		#"policy": ?
		"name": name,
		"description": e["descripion"] if "description" in e else "",
		"source_zones": [
			possibly_add_and_get_zone_db_id_by_name(zone_name)
			for zone_name in e["from"]["member"]
		],
		"destination_zones": [
			possibly_add_and_get_zone_db_id_by_name(zone_name)
			for zone_name in e["to"]["member"]
		],
		"source": [
			object_db_id_by_fw_name[object_name]
			for object_name in e["source"]["member"]
		],
		"destination": [
			object_db_id_by_fw_name[object_name]
			for object_name in e["destination"]["member"]
		],
		"dst_port": [object_db_id_by_fw_name["any"]], #TODO
		"protocol": {
			"service-http" : "http",
			"service-https" : "https",
		}.get(
			services[0],
			"" # default
		),
		"application": [
			possibly_add_and_get_application_db_id_by_name(app_name)
			for app_name in e["application"]["member"]
		],
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

for e in pan_fetch_nat_rules():
	position = len(nat_rules_ids) + 1
	name = e["@name"]

	if len(e["to"]["member"]) > 1: raise RuntimeError(
		"more than one destination zone?"
	)

	params = {
		"product": product_id,
		"position": position,
		"name": name,
		"description": e["description"] if "description" in e else "",
		"source_zones": [
			possibly_add_and_get_zone_db_id_by_name(zone_name)
			for zone_name in e["from"]["member"]
		],
		"destination_zone": possibly_add_and_get_zone_db_id_by_name(
			e["to"]["member"][0]
		),
		"orignal_src_ip":
			object_db_id_by_fw_name[e["source"]["member"][0]],
		"original_dst_ip":
			object_db_id_by_fw_name[e["destination"]["member"][0]],
		"original_port": ""
	}

	source_translation_type = list(e["source-translation"].keys())[0]
	source_translation = e["source-translation"][source_translation_type]
	translated_object_type = list(source_translation.keys())[0]
	translated_object = source_translation[translated_object_type]

	def translated_addresses():
		translated_addresses = translated_object["member"]
		params["translated_src_ip"] = [
			object_db_id_by_fw_name[address_name]
			for address_name in translated_addresses
		]

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
		"fw_objects": objects_db_ids
	}
)
if response.text == "Error": raise RuntimeError(
	f"couldn't add configuration named \"{configuration_name}\""
)
print("success")