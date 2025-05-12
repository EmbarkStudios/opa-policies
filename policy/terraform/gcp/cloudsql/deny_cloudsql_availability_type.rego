package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check48 := "TF_GCP_48"

# DENY(TF_GCP_48)
deny_cloudsql_availability_type contains msg if {
	input.resource.google_sql_database_instance
	instance := input.resource.google_sql_database_instance[i]
	not make_exception(check48, instance)
	not instance.settings.availability_type == "REGIONAL"

	msg = sprintf("%s: Ensure instance is REGIONAL [%s]. More info: %s", [check48, instance.name, l.get_url(check48)])
}
