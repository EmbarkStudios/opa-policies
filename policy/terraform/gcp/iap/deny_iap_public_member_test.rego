package terraform_gcp

import data.terraform

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

    deny_iap_public_member with input as input
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

    not deny_iap_public_member[sprintf("TF_GCP_12: public users (%s) not allowed. More info: %s", [get_url(check12)])] with input as input
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

    deny_iap_public_member with input as input
}
