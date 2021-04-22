package terraform_gcp

import data.terraform

test_deny_public_iam_member {
    input := {
        "resource": {
            "google_storage_bucket_iam_binding": {
                "public-member": {
                    "bucket": "a bucket",
                    "role": "roles/storage.admin",
                    "members": ["allUsers", "group:test@embark.dev"]
                }
            }
        }
    }

    deny_public_iam_binding with input as input
}

test_not_deny_public_iam_member_when_exception {
    input := {
        "resource": {
            "google_storage_bucket_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_03",
                    "bucket": "embark-public",
                    "role": "roles/storage.admin",
                    "members": ["allUsers", "group:test@embark.dev"]
                }
            }
        }
    }

    not deny_public_iam_binding[sprintf("TF_GCP_03: public users not allowed for bucket: embark-public. More info: %s", [get_url(check03)])] with input as input
}

test_deny_public_iam_member_more_members {
    input := {
        "resource": {
            "google_storage_bucket_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_03",
                    "bucket": "embark-public",
                    "role": "roles/storage.admin",
                    "members": ["allUsers", "group:test@embark.dev"]
                },
                "should be blocked": {
                    "bucket": "a bucket",
                    "role": "roles/storage.admin",
                    "members": ["allUsers", "group:test@embark.dev"]
                },
                "should not be blocked": {
                    "bucket": "a bucket",
                    "role": "roles/storage.admin",
                    "members": ["group:test@embark.dev"]
                }
            }
        }
    }

    deny_public_iam_binding with input as input
}
