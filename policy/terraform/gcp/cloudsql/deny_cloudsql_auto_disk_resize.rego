package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check47 := "TF_GCP_47"

# DENY(TF_GCP_47)
deny_cloudsql_auto_disk_resize contains msg if {
	input.resource.google_sql_database_instance
	instance := input.resource.google_sql_database_instance[i]
	not make_exception(check47, instance)
	l.is_false(instance.settings.disk_autoresize)

	msg = sprintf("%s: Ensure auto disk resize enabled on [%s]. More info: %s", [check47, instance.name, l.get_url(check47)])
}
