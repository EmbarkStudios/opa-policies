package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check06 := "TF_GCP_06"

# DENY(TF_GCP_06)
deny_project_auto_created_network contains msg if {
	input.resource.google_project
	p := input.resource.google_project[_]
	not make_exception(check06, p)

	l.not_existing_or_true(p, "auto_create_network")

	msg = sprintf("%s: auto created networks are not allowed for project %s. More info: %s", [check06, p.name, l.get_url(check06)])
}
