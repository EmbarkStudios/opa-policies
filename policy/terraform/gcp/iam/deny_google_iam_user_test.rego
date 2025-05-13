package terraform_gcp

import rego.v1

import data.testing as t

test_deny_user_org_member if {
	inp := {"resource": {"google_organization_iam_member": {"public-member": {
		"role": "roles/container.developer",
		"member": "user:test@domain.com",
	}}}}

	t.error_count(deny_user_org_member, 1) with input as inp
}

test_not_deny_deny_user_org_member_when_exception if {
	inp := {"resource": {"google_organization_iam_member": {"public-member": {
		"//": "TF_GCP_44",
		"role": "roles/container.developer",
		"member": "user:test@domain.com",
	}}}}

	t.no_errors(deny_user_org_member) with input as inp
}

test_not_deny_deny_user_org_member_when_group if {
	inp := {"resource": {"google_organization_iam_member": {"public-member": {
		"role": "roles/container.developer",
		"member": "group:test@domain.com",
	}}}}

	t.no_errors(deny_user_org_member) with input as inp
}

test_deny_user_org_more_members if {
	inp := {"resource": {"google_organization_iam_member": {
		"public-member": {
			"//": "TF_GCP_44",
			"role": "roles/container.developer",
			"member": "user:test@domain.com",
		},
		"should be blocked": {
			"role": "roles/container.developer",
			"member": "user:test2@domain.com",
		},
	}}}

	t.error_count(deny_user_org_member, 1) with input as inp
}
