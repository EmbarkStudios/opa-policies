package terraform_gcp

import rego.v1

import data.testing as t

test_deny_impersonation_roles_org_member if {
	inp := {"resource": {"google_organization_iam_binding": {"public-member": {
		"role": "roles/iam.serviceAccountTokenCreator",
		"members": ["group:test@domain.com"],
	}}}}

	t.error_count(deny_impersonation_roles_org_binding, 1) with input as inp
}

test_not_deny_impersonation_roles_org_member_when_exception if {
	inp := {"resource": {"google_organization_iam_binding": {"public-member": {
		"//": "TF_GCP_18",
		"role": "roles/iam.serviceAccountTokenCreator",
		"members": ["group:test@domain.com"],
	}}}}

	t.no_errors(deny_impersonation_roles_org_binding) with input as inp
}

test_deny_default_sa_org_member_more_members if {
	inp := {"resource": {"google_organization_iam_binding": {
		"public-member": {
			"//": "TF_GCP_18",
			"role": "roles/iam.serviceAccountTokenCreator",
			"members": ["group:test@domain.com"],
		},
		"should be blocked": {
			"role": "roles/iam.serviceAccountTokenCreator",
			"members": ["group:test@domain.com"],
		},
	}}}

	t.error_count(deny_impersonation_roles_org_binding, 1) with input as inp
}
