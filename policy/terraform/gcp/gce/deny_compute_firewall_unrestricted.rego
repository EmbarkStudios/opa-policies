package terraform_gcp

import data.lib as l
import data.terraform

check14 := "TF_GCP_14"

# DENY(TF_GCP_14)
deny_compute_firewall_unrestricted[msg] {
	input.resource.google_compute_firewall
	f := input.resource.google_compute_firewall[i]
	f.allow
	f.source_ranges
	l.contains_element(f.source_ranges, "0.0.0.0/0")
	not make_exception(check14, f)

	msg = sprintf("%s: firewall rule: %s is unrestricted (0.0.0.0/0). More info: %s", [check14, f.name, l.get_url(check14)])
}
