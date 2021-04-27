package terraform_gcp

import data.testing as t

test_deny_iap_public_member {
    input := {
        "resource": {
            "google_iap_web_iam_member": {
                "public-member": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "allUsers"
                }
            }
        }
    }

    t.error_count(deny_iap_public_member, 1) with input as input
}

test_not_deny_iap_public_member_when_exception {
    input := {
        "resource": {
            "google_iap_web_iam_member": {
                "public-member": {
                    "//": "TF_GCP_12",
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "allUsers"
                }
            }
        }
    }

    t.no_errors(deny_iap_public_member) with input as input
}

test_deny_iap_public_member_more_members {
    input := {
        "resource": {
            "google_iap_web_iam_member": {
                "public-member": {
                    "//": "TF_GCP_12",
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "allUsers"
                },
                "should be blocked": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "allUsers"
                }
            }
        }
    }

    t.error_count(deny_iap_public_member, 1) with input as input
}
