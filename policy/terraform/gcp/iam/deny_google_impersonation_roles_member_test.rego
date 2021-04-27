package terraform_gcp

import data.terraform

test_deny_impersonation_roles_org_member {
    input := {
        "resource": {
            "google_organization_iam_member": {
                "public-member": {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "member": "test@domain.com"
                }
            }
        }
    }

    error_count(deny_impersonation_roles_org_member, 1) with input as input
}

test_not_deny_impersonation_roles_org_member_when_exception {
    input := {
        "resource": {
            "google_organization_iam_member": {
                "public-member": {
                    "//": "TF_GCP_17",
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "member": "test@domain.com"
                }
            }
        }
    }

    no_errors(deny_impersonation_roles_org_member) with input as input
}

test_deny_default_sa_org_member_more_members {
    input := {
        "resource": {
            "google_organization_iam_member": {
                "public-member": {
                    "//": "TF_GCP_17",
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "member": "test@domain.com"
                },
                "should be blocked": {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "member": "test2@domain.com"
                }
            }
        }
    }

    error_count(deny_impersonation_roles_org_member, 1) with input as input
}
