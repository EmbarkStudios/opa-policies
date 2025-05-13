package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check39 := "TF_GCP_39"

oslogin_not_enabled(instance) if {
	not instance.metadata["enable-oslogin"]
} else if {
	oslogin_enabled := instance.metadata["enable-oslogin"]
	oslogin_enabled != "TRUE"
}

# DENY(TF_GCP_39)
deny_compute_instance_oslogin_disabled contains msg if {
	input.resource.google_compute_instance
	instance := input.resource.google_compute_instance[_]

	not make_exception(check39, instance)

	oslogin_not_enabled(instance)

	msg = sprintf("%s: compute instance: %s does not have OS Login enabled. More info: %s", [check39, instance.name, l.get_url(check39)])
}
