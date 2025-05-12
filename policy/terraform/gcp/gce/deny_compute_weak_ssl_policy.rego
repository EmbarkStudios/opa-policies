package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check11 := "TF_GCP_11"

# DENY(TF_GCP_11)
deny_compute_weak_ssl_policy contains msg if {
	input.resource.google_compute_ssl_policy
	p := input.resource.google_compute_ssl_policy[i]
	not l.contains_element(["MODERN", "RESTRICTED"], p.profile)
	not make_exception(check11, p)

	msg = sprintf("%s: ssl policy: %s has a weak profile: %s. More info: %s", [check11, p.name, p.profile, l.get_url(check11)])
}
