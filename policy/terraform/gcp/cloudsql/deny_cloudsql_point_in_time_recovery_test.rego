package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_cloudsql_with_pitr if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"backup_configuration": {"point_in_time_recovery_enabled": true}},
	}}}}

	t.no_errors(deny_cloudsql_point_in_time_recovery) with input as inp
}

test_deny_cloudsql_no_pitr_without_conf if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {},
	}}}}

	t.error_count(deny_cloudsql_point_in_time_recovery, 1) with input as inp
}

test_not_deny_cloudsql_pitr_as_string if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"backup_configuration": {"point_in_time_recovery_enabled": "true"}},
	}}}}

	t.no_errors(deny_cloudsql_point_in_time_recovery) with input as inp
}

test_deny_cloudsql_pitr_no_prop if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"backup_configuration": {"backup_retention_settings": {"retained_backups": 14}}},
	}}}}

	t.error_count(deny_cloudsql_point_in_time_recovery, 1) with input as inp
}

test_not_deny_cloudsql_no_pitr_when_exception if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"//": "TF_GCP_52",
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"backup_configuration": {"point_in_time_recovery_enabled": "false"}},
	}}}}

	t.no_errors(deny_cloudsql_point_in_time_recovery) with input as inp
}

test_deny_cloudsql_no_pitr_with_string if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"backup_configuration": {"point_in_time_recovery_enabled": "false"}},
	}}}}

	t.error_count(deny_cloudsql_point_in_time_recovery, 1) with input as inp
}

test_deny_cloudsql_no_pitr if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"backup_configuration": {"point_in_time_recovery_enabled": false}},
	}}}}

	t.error_count(deny_cloudsql_point_in_time_recovery, 1) with input as inp
}

test_not_deny_cloudsql_no_pitr_when_not_postgres if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "MYSQL_8_0",
		"settings": {"backup_configuration": {"point_in_time_recovery_enabled": "false"}},
	}}}}

	t.no_errors(deny_cloudsql_point_in_time_recovery) with input as inp
}
