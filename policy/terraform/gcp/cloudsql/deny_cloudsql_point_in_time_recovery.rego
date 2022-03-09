package terraform_gcp

import data.lib as l
import data.terraform

check52 := "TF_GCP_52"

no_pitr(instance) {
	not instance.settings.backup_configuration.point_in_time_recovery_enabled
} else {
	not l.is_true(instance.settings.backup_configuration.point_in_time_recovery_enabled)
}

# DENY(TF_GCP_46)
deny_cloudsql_point_in_time_recovery[msg] {
	input.resource.google_sql_database_instance
	instance := input.resource.google_sql_database_instance[i]
	not make_exception(check52, instance)
	contains(instance.database_version, "POSTGRES")
	no_pitr(instance)

	msg = sprintf("%s: Ensure point in time recovery is enabled on [%s]. More info: %s", [check52, instance.name, l.get_url(check52)])
}
