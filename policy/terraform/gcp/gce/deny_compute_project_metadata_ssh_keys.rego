package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check40 := "TF_GCP_40"

# DENY(TF_GCP_40)
deny_compute_project_metadata_ssh_keys contains msg if {
	input.resource.google_compute_project_metadata
	project_meta := input.resource.google_compute_project_metadata[name]

	not make_exception(check40, project_meta)

	project_meta.metadata[key]
	key == "ssh-keys"

	msg = sprintf("%s: compute project metadata: %s wants to set project-wide ssh keys. More info: %s", [check40, name, l.get_url(check40)])
}

deny_compute_project_metadata_item_ssh_keys contains msg if {
	input.resource.google_compute_project_metadata_item
	project_meta_item := input.resource.google_compute_project_metadata_item[name]

	not make_exception(check40, project_meta_item)

	project_meta_item.key == "ssh-keys"

	msg = sprintf("%s: compute project metadata item: %s wants to set project-wide ssh keys. More info: %s", [check40, name, l.get_url(check40)])
}
