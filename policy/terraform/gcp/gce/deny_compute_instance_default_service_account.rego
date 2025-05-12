package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check36 := "TF_GCP_36"

instance_using_default_svc_acc(instance) if {
	not instance.service_account
} else if {
	svc_acc := instance.service_account.email
	regex.match(default_service_account_regexp, svc_acc)
}

# DENY(TF_GCP_36)
deny_compute_instance_default_service_account contains msg if {
	input.resource.google_compute_instance
	instance := input.resource.google_compute_instance[_]
	not make_exception(check36, instance)

	instance_using_default_svc_acc(instance)

	msg = sprintf("%s: compute instance: %s is using the default service account. More info: %s", [check36, instance.name, l.get_url(check36)])
}
