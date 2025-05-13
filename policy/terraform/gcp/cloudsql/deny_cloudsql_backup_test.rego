package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_cloudsql_no_backup if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"settings": {"backup_configuration": {"enabled": true}},
	}}}}

	t.no_errors(deny_cloudsql_no_backup) with input as inp
}

test_deny_cloudsql_no_backup_without_conf if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"settings": {},
	}}}}

	t.error_count(deny_cloudsql_no_backup, 1) with input as inp
}

test_not_deny_cloudsql_no_backup_as_string if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"settings": {"backup_configuration": {"enabled": "true"}},
	}}}}

	t.no_errors(deny_cloudsql_no_backup) with input as inp
}

test_not_deny_cloudsql_no_backup_no_prop if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"settings": {"backup_configuration": {"backup_retention_settings": {"retained_backups": 14}}},
	}}}}

	t.no_errors(deny_cloudsql_no_backup) with input as inp
}

test_not_deny_cloudsql_no_backup_when_exception if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"//": "TF_GCP_46",
		"name": "test",
		"settings": {"backup_configuration": {"enabled": "false"}},
	}}}}

	t.no_errors(deny_cloudsql_no_backup) with input as inp
}

test_deny_deny_cloudsql_no_backup_with_string if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"settings": {"backup_configuration": {"enabled": "false"}},
	}}}}

	t.error_count(deny_cloudsql_no_backup, 1) with input as inp
}

test_deny_deny_cloudsql_no_backup if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"settings": {"backup_configuration": {"enabled": false}},
	}}}}

	t.error_count(deny_cloudsql_no_backup, 1) with input as inp
}
