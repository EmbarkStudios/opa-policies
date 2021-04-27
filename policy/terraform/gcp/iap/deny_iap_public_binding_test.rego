package terraform_gcp

import data.terraform

test_deny_iap_public_binding {
    input := {
        "resource": {
            "google_iap_web_iam_binding": {
                "public-member": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "members": ["allUsers", "group:test@embark.dev"]
                }
            }
        }
    }

    error_count(deny_iap_public_binding, 1) with input as input
}

test_not_deny_iap_public_binding_when_exception {
    input := {
        "resource": {
            "google_iap_web_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_13",
                    "role": "roles/iap.httpsResourceAccessor",
                    "members": ["group:test@embark.dev"]
                }
            }
        }
    }

    no_errors(deny_iap_public_binding) with input as input
}

test_deny_iap_public_binding_more_members {
    input := {
        "resource": {
            "google_iap_web_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_13",
                    "role": "roles/iap.httpsResourceAccessor",
                    "members": ["allUsers", "group:test@embark.dev"]
                },
                "should be blocked": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "members": ["allUsers", "group:test@embark.dev"]
                }
            }
        }
    }

    error_count(deny_iap_public_binding, 1) with input as input
}
