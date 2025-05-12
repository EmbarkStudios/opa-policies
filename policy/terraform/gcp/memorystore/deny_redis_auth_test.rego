package terraform_gcp

import rego.v1

import data.testing as t

test_deny_memorystore_redis_no_auth_no_prop if {
	inp := {"resource": {"google_redis_instance": {"test": {"name": "test"}}}}

	t.error_count(deny_memorystore_redis_no_auth, 1) with input as inp
}

test_deny_memorystore_redis_no_auth_false_string if {
	inp := {"resource": {"google_redis_instance": {"test": {
		"name": "test",
		"auth_enabled": "false",
	}}}}

	t.error_count(deny_memorystore_redis_no_auth, 1) with input as inp
}

test_deny_memorystore_redis_no_auth_false_native if {
	inp := {"resource": {"google_redis_instance": {"test": {
		"name": "test",
		"auth_enabled": false,
	}}}}

	t.error_count(deny_memorystore_redis_no_auth, 1) with input as inp
}

test_not_deny_memorystore_redis_no_auth_with_exception if {
	inp := {"resource": {"google_redis_instance": {"test": {
		"//": "TF_GCP_49",
		"name": "test",
		"auth_enabled": "false",
	}}}}

	t.no_errors(deny_memorystore_redis_no_auth) with input as inp
}
