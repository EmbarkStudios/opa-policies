package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_iam_policy_with_exclusions if {
	inp := {
		"data": {"google_iam_policy": {"p": {"binding": [
			{
				"role": "roles/storage.admin",
				"members": ["group:test@domain.com"],
			},
			{
				"//": "TF_GCP_04",
				"role": "roles/storage.admin",
				"members": ["allAuthenticatedUsers"],
			},
		]}}},
		"resource": {
			"google_storage_bucket": {"b": {
				"name": "b",
				"location": "EUROPE-WEST4",
				"storage_class": "STANDARD",
				"uniform_bucket_level_access": "true",
			}},
			"google_storage_bucket_iam_policy": {"b": {
				"bucket": "${google_storage_bucket.b.name}",
				"policy_data": "${data.google_iam_policy.p.policy_data}",
			}},
		},
	}

	t.no_errors(deny_iam_policy) with input as inp
}

test_deny_iam_policy if {
	inp := {
		"data": {"google_iam_policy": {"p": {"binding": [{
			"role": "roles/storage.admin",
			"members": ["allUsers"],
		}]}}},
		"resource": {
			"google_storage_bucket": {"b": {
				"name": "b",
				"location": "EUROPE-WEST4",
				"storage_class": "STANDARD",
				"uniform_bucket_level_access": "true",
			}},
			"google_storage_bucket_iam_policy": {"b": {
				"bucket": "${google_storage_bucket.b.name}",
				"policy_data": "${data.google_iam_policy.p.policy_data}",
			}},
		},
	}

	t.error_count(deny_iam_policy, 1) with input as inp
}

test_not_deny_iam_policy if {
	inp := {
		"data": {"google_iam_policy": {"p": {"binding": [{
			"role": "roles/storage.admin",
			"members": ["group:test@domain.com"],
		}]}}},
		"resource": {
			"google_storage_bucket": {"b": {
				"name": "b",
				"location": "EUROPE-WEST4",
				"storage_class": "STANDARD",
				"uniform_bucket_level_access": "true",
			}},
			"google_storage_bucket_iam_policy": {"b": {
				"bucket": "${google_storage_bucket.b.name}",
				"policy_data": "${data.google_iam_policy.p.policy_data}",
			}},
		},
	}

	t.no_errors(deny_iam_policy) with input as inp
}
