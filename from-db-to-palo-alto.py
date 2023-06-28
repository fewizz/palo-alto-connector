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

#objects_ids = configuration["fw_objects"]

