package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check46 := "TF_GCP_46"

no_backup_config(instance) if {
	not instance.settings.backup_configuration
} else if {
	l.is_false(instance.settings.backup_configuration.enabled)
}

# DENY(TF_GCP_46)
deny_cloudsql_no_backup contains msg if {
	input.resource.google_sql_database_instance
	instance := input.resource.google_sql_database_instance[i]
	not make_exception(check46, instance)
	no_backup_config(instance)

	msg = sprintf("%s: Ensure auto backups are enabled on [%s]. More info: %s", [check46, instance.name, l.get_url(check46)])
}
