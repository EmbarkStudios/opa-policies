package terraform_gcp

import data.lib as l
import data.terraform

check53 := "TF_GCP_53"

mysql_expected_flags := {{"name": "local_infile", "value": "off"}}

# DENY(TF_GCP_53)
deny_cloudsql_mysql_flags[msg] {
	input.resource.google_sql_database_instance
	instance := input.resource.google_sql_database_instance[i]
	not make_exception(check53, instance)
	flags := {flag | flag := instance.settings.database_flags[_]}
	intersect := mysql_expected_flags & flags
	not count(intersect) == count(mysql_expected_flags)

	msg = sprintf("%s: Ensure database flags are set [%s]. More info: %s", [check53, instance.name, l.get_url(check53)])
}
