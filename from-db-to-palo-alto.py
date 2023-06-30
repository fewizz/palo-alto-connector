from palo_alto_common import *

print(
	f"fetching configuration named \"{configuration_name}\" from DB... ",
	end = ""
)
response = requests.get(
	f"{fwmt_address}/config/{configuration_name}"
)
if response.text == "Error": raise RuntimeError(
	f"couldn't fetch configuration named \"{configuration_name}\" from DB"
)
configuration = json.loads(response.text)[0]
configuration_id = configuration["id"]
# i HAVE to do this for some reason...
response = requests.get(
	f"{fwmt_address}/config/id/{configuration_id}"
)
configuration = json.loads(response.text)[0]
print("success")

security_rules_ids = configuration["security_rules"]
nat_rules_ids = configuration["nat_rules"]

# objects
pan_addresses = pan_fetch_addresses()

# security rules
pan_security_rules = pan_fetch_security_rules()

for security_rule_id in security_rules_ids:
	response = requests.get(
		f"{fwmt_address}/sec_rule/id/{security_rule_id}"
	)
	if response.text == "Error": raise RuntimeError(
		f"couldn't fetch security rule with id \"{security_rule_id}\" from DB"
	)
	security_rule = json.loads(response.text)[0]
	name = security_rule["name"]

	pan_security_rule = next(
		filter(lambda sr: sr["@name"] == name, pan_security_rules),
		None
	)

	data = pan_security_rule if pan_security_rule != None else {}
