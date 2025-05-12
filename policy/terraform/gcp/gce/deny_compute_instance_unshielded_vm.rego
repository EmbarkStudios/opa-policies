package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check20 := "TF_GCP_20"

secure_boot_not_enabled(instance) if {
	not instance.shielded_instance_config.secure_boot_enabled
} else if {
	sbe := instance.shielded_instance_config.secure_boot_enabled
	l.is_false(sbe)
}

# DENY(TF_GCP_20)
deny_compute_instance_unshielded_vm contains msg if {
	input.resource.google_compute_instance
	instance := input.resource.google_compute_instance[_]
	not make_exception(check20, instance)

	secure_boot_not_enabled(instance)

	msg = sprintf("%s: compute instance: %s does not have secure boot enabled. More info: %s", [check20, instance.name, l.get_url(check20)])
}
