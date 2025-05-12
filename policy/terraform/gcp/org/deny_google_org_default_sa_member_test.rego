package terraform_gcp

import rego.v1

import data.testing as t

test_deny_default_sa_org_member if {
	inp := {"resource": {"google_organization_iam_member": {"public-member": {
		"role": "roles/iap.httpsResourceAccessor",
		"member": "88888888-compute@developer.gserviceaccount.com",
	}}}}

	t.error_count(deny_default_sa_member_on_org_level, 1) with input as inp
}

test_not_deny_default_sa_org_member_when_exception if {
	inp := {"resource": {"google_organization_iam_member": {"public-member": {
		"//": "TF_GCP_15",
		"role": "roles/iap.httpsResourceAccessor",
		"member": "88888888-compute@developer.gserviceaccount.com",
	}}}}

	t.no_errors(deny_default_sa_member_on_org_level) with input as inp
}

test_deny_default_sa_org_member_more_members if {
	inp := {"resource": {"google_organization_iam_member": {
		"public-member": {
			"//": "TF_GCP_15",
			"role": "roles/iap.httpsResourceAccessor",
			"member": "88888888-compute@developer.gserviceaccount.com",
		},
		"should be blocked": {
			"role": "roles/iap.httpsResourceAccessor",
			"member": "7777777-compute@developer.gserviceaccount.com",
		},
	}}}

	t.error_count(deny_default_sa_member_on_org_level, 1) with input as inp
}
