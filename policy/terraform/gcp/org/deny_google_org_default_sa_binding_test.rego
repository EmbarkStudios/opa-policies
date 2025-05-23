package terraform_gcp

import rego.v1

import data.testing as t

test_deny_default_sa_org_binding if {
	inp := {"resource": {"google_organization_iam_binding": {"public-member": {
		"role": "roles/iap.httpsResourceAccessor",
		"members": ["test@test.com", "88888888-compute@developer.gserviceaccount.com"],
	}}}}

	t.error_count(deny_default_sa_binding_on_org_level, 1) with input as inp
}

test_not_deny_default_sa_org_binding_when_exception if {
	inp := {"resource": {"google_organization_iam_binding": {"public-member": {
		"//": "TF_GCP_16",
		"role": "roles/iap.httpsResourceAccessor",
		"members": ["88888888-compute@developer.gserviceaccount.com"],
	}}}}

	t.no_errors(deny_default_sa_binding_on_org_level) with input as inp
}

test_deny_default_sa_org_binding_more_members if {
	inp := {"resource": {"google_organization_iam_binding": {
		"public-member": {
			"//": "TF_GCP_16",
			"role": "roles/iap.httpsResourceAccessor",
			"members": ["88888888-compute@developer.gserviceaccount.com"],
		},
		"should be blocked": {
			"role": "roles/iap.httpsResourceAccessor",
			"members": ["7777777-compute@developer.gserviceaccount.com"],
		},
	}}}

	t.error_count(deny_default_sa_binding_on_org_level, 1) with input as inp
}
