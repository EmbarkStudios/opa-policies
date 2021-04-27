package terraform_gcp

import data.terraform

test_deny_default_sa_org_binding {
    input := {
        "resource": {
            "google_organization_iam_binding": {
                "public-member": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "members": ["test@test.com","88888888-compute@developer.gserviceaccount.com"]
                }
            }
        }
    }

    error_count(deny_default_sa_binding_on_org_level, 1) with input as input
}

test_not_deny_default_sa_org_binding_when_exception {
    input := {
        "resource": {
            "google_organization_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_16",
                    "role": "roles/iap.httpsResourceAccessor",
                    "members": ["88888888-compute@developer.gserviceaccount.com"]
                }
            }
        }
    }

    no_errors(deny_default_sa_binding_on_org_level) with input as input
}

test_deny_default_sa_org_binding_more_members {
    input := {
        "resource": {
            "google_organization_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_16",
                    "role": "roles/iap.httpsResourceAccessor",
                    "members": ["88888888-compute@developer.gserviceaccount.com"]
                },
                "should be blocked": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "members": ["7777777-compute@developer.gserviceaccount.com"]
                }
            }
        }
    }

    error_count(deny_default_sa_binding_on_org_level, 1) with input as input
}
