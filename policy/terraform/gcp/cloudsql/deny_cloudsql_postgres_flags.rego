package terraform_gcp

import data.lib as l
import data.terraform

check54 := "TF_GCP_54"

postgres_expected_flags := {
	{"name": "log_checkpoints", "value": "on"},
	{"name": "log_connections", "value": "on"},
	{"name": "log_disconnections", "value": "on"},
	{"name": "log_lock_waits", "value": "on"},
}

# DENY(TF_GCP_54)
deny_cloudsql_postgres_flags[msg] {
	input.resource.google_sql_database_instance
	instance := input.resource.google_sql_database_instance[i]
	not make_exception(check54, instance)
	contains(instance.database_version, "POSTGRES")
	flags := {flag | flag := instance.settings.database_flags[_]}
	intersect := postgres_expected_flags & flags
	not count(intersect) == count(postgres_expected_flags)

	msg = sprintf("%s: Ensure database flags are set [%s]. More info: %s", [check54, instance.name, l.get_url(check54)])
}
