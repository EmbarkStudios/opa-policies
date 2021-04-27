package terraform_gcp

import data.terraform

check20 := "TF_GCP_20"

secure_boot_not_enabled(instance) {
	not instance.shielded_instance_config.secure_boot_enabled
} else {
	sbe := instance.shielded_instance_config.secure_boot_enabled
	is_false(sbe)
}

# DENY(TF_GCP_20)
deny_compute_instance_unshielded_vm[msg] {
	input.resource.google_compute_instance
	instance := input.resource.google_compute_instance[_]
	not make_exception(check20, instance)
	
	secure_boot_not_enabled(instance)

	msg = sprintf("%s: compute instance: %s does not have secure boot enabled. More info: %s", [check20, instance.name, get_url(check20)])
}
