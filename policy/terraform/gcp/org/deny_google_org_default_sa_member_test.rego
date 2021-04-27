package terraform_gcp

import data.terraform

test_deny_default_sa_org_member {
    input := {
        "resource": {
            "google_organization_iam_member": {
                "public-member": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "88888888-compute@developer.gserviceaccount.com"
                }
            }
        }
    }

    error_count(deny_default_sa_member_on_org_level, 1) with input as input
}

test_not_deny_default_sa_org_member_when_exception {
    input := {
        "resource": {
            "google_organization_iam_member": {
                "public-member": {
                    "//": "TF_GCP_15",
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "88888888-compute@developer.gserviceaccount.com"
                }
            }
        }
    }

    no_errors(deny_default_sa_member_on_org_level) with input as input
}

test_deny_default_sa_org_member_more_members {
    input := {
        "resource": {
            "google_organization_iam_member": {
                "public-member": {
                    "//": "TF_GCP_15",
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "88888888-compute@developer.gserviceaccount.com"
                },
                "should be blocked": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "7777777-compute@developer.gserviceaccount.com"
                }
            }
        }
    }

    error_count(deny_default_sa_member_on_org_level, 1) with input as input
}
