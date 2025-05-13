package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_cloudsql_postgres_flags if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"database_flags": [
			{"name": "log_checkpoints", "value": "on"},
			{"name": "log_connections", "value": "on"},
			{"name": "log_disconnections", "value": "on"},
			{"name": "log_lock_waits", "value": "on"},
			{"name": "log_temp_files", "value": "0"},
			{"name": "log_min_duration_statement", "value": "-1"},
		]},
	}}}}

	t.no_errors(deny_cloudsql_postgres_flags) with input as inp
}

test_not_deny_cloudsql_postgres_flags if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "SQLSERVER_2019_STANDARD",
		"settings": {},
	}}}}

	t.no_errors(deny_cloudsql_postgres_flags) with input as inp
}

test_not_deny_cloudsql_postgres_flags_additional_flag if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"database_flags": [
			{"name": "log_disconnections", "value": "on"},
			{"name": "log_connections", "value": "on"},
			{"name": "log_checkpoints", "value": "on"},
			{"name": "log_lock_waits", "value": "on"},
			{"name": "log_temp_files", "value": "0"},
			{"name": "log_min_duration_statement", "value": "-1"},
			{"name": "a_flag", "value": "on"},
		]},
	}}}}

	t.no_errors(deny_cloudsql_postgres_flags) with input as inp
}

test_deny_cloudsql_postgres_flags_missing if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"database_flags": [
			{"name": "log_checkpoints", "value": "on"},
			{"name": "log_connections", "value": "on"},
			{"name": "log_disconnections", "value": "on"},
		]},
	}}}}

	t.error_count(deny_cloudsql_postgres_flags, 1) with input as inp
}

test_not_deny_cloudsql_postgres_flags_missing if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"//": "TF_GCP_54",
		"name": "test",
		"database_version": "POSTGRES_13",
		"settings": {"database_flags": [
			{"name": "log_checkpoints", "value": "on"},
			{"name": "log_connections", "value": "on"},
			{"name": "log_disconnections", "value": "on"},
		]},
	}}}}

	t.no_errors(deny_cloudsql_postgres_flags) with input as inp
}
