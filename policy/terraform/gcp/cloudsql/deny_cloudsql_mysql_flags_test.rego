package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_cloudsql_mysql_flags if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "MYSQL_8_0",
		"settings": {"database_flags": [{"name": "local_infile", "value": "off"}]},
	}}}}

	t.no_errors(deny_cloudsql_mysql_flags) with input as inp
}

test_deny_cloudsql_mysql_flags_empty if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "MYSQL_8_0",
		"settings": {"database_flags": []},
	}}}}

	t.error_count(deny_cloudsql_mysql_flags, 1) with input as inp
}

test_deny_cloudsql_mysql_flags_no_prop if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "MYSQL_8_0",
		"settings": {},
	}}}}

	t.error_count(deny_cloudsql_mysql_flags, 1) with input as inp
}

test_not_deny_cloudsql_mysql_flags_when_exception if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "MYSQL_8_0",
		"//": "TF_GCP_53",
		"settings": {"database_flags": []},
	}}}}

	t.no_errors(deny_cloudsql_mysql_flags) with input as inp
}

test_deny_cloudsql_mysql_flags_wrong_flag if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "MYSQL_8_0",
		"settings": {"database_flags": [{"name": "not_existing", "value": "off"}]},
	}}}}

	t.error_count(deny_cloudsql_mysql_flags, 1) with input as inp
}

test_not_deny_cloudsql_mysql_flags_multiple if {
	inp := {"resource": {"google_sql_database_instance": {"test": {
		"name": "test",
		"database_version": "MYSQL_8_0",
		"settings": {"database_flags": [
			{"name": "local_infile", "value": "off"},
			{"name": "not_existing", "value": "off"},
		]},
	}}}}

	t.no_errors(deny_cloudsql_mysql_flags) with input as inp
}
