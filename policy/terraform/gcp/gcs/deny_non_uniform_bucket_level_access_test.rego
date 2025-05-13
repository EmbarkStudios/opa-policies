package terraform_gcp

import rego.v1

import data.testing as t

test_deny_uniform_level_access_exception if {
	inp := {"resource": {"google_storage_bucket": {"b3": {
		"name": "b3",
		"//": "TF_GCP_01",
		"uniform_bucket_level_access": false,
		"location": "eu",
		"storage_class": "STANDARD",
	}}}}

	t.no_errors(deny_non_uniform_level_access) with input as inp
}

test_deny_uniform_level_access if {
	inp := {"resource": {"google_storage_bucket": {
		"b1": {
			"name": "b1",
			"uniform_bucket_level_access": true,
			"location": "eu",
			"storage_class": "STANDARD",
		},
		"b2": {
			"name": "b2",
			"uniform_bucket_level_access": "false",
			"location": "eu",
			"storage_class": "STANDARD",
		},
	}}}

	t.error_count(deny_non_uniform_level_access, 1) with input as inp
}

test_deny_uniform_level_access_all if {
	inp := {"resource": {"google_storage_bucket": {
		"b1": {
			"name": "b1",
			"uniform_bucket_level_access": true,
			"location": "eu",
			"storage_class": "STANDARD",
		},
		"b2": {
			"name": "b2",
			"uniform_bucket_level_access": false,
			"location": "eu",
			"storage_class": "STANDARD",
		},
		"b3": {
			"name": "b3",
			"//": "TF_GCP_01",
			"uniform_bucket_level_access": false,
			"location": "eu",
			"storage_class": "STANDARD",
		},
	}}}

	t.error_count(deny_non_uniform_level_access, 1) with input as inp
}
