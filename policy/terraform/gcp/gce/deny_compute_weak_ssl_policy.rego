package terraform_gcp

import data.terraform

check11 := "TF_GCP_11"

# DENY(TF_GCP_11)
deny_compute_weak_ssl_policy[msg] {
	input.resource.google_compute_ssl_policy
	p := input.resource.google_compute_ssl_policy[i]
	not contains_element(["MODERN", "RESTRICTED"], p.profile)
	not make_exception(check11, p)

	msg = sprintf("%s: ssl policy: %s has a weak profile: %s. More info: %s", [check11, p.name, p.profile, get_url(check11)])
}
