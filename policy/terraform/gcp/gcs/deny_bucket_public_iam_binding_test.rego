package terraform_gcp

import data.testing as t

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

    t.error_count(deny_public_iam_binding, 1) with input as input
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

    t.no_errors(deny_public_iam_binding) with input as input
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

    t.error_count(deny_public_iam_binding, 1) with input as input
}
