package terraform_gcp

import data.terraform

test_deny_bucket_public_iam_member {
    input := {
        "resource": {
            "google_storage_bucket_iam_member": {
                "public-member": {
                    "bucket": "a bucket",
                    "role": "roles/storage.admin",
                    "member": "allUsers"
                }
            }
        }
    }

    error_count(deny_bucket_public_iam_member, 1) with input as input
}

test_not_deny_bucket_public_iam_member_when_exception {
    input := {
        "resource": {
            "google_storage_bucket_iam_member": {
                "public-member": {
                    "//": "TF_GCP_02",
                    "bucket": "embark-public",
                    "role": "roles/storage.admin",
                    "member": "allUsers"
                }
            }
        }
    }

    no_errors(deny_bucket_public_iam_member) with input as input
}

test_deny_bucket_public_iam_member_more_members {
    input := {
        "resource": {
            "google_storage_bucket_iam_member": {
                "public-member": {
                    "//": "TF_GCP_02",
                    "bucket": "embark-public",
                    "role": "roles/storage.admin",
                    "member": "allUsers"
                },
                "should be blocked": {
                    "bucket": "a bucket",
                    "role": "roles/storage.admin",
                    "member": "allUsers"
                }
            }
        }
    }

    error_count(deny_bucket_public_iam_member, 1) with input as input
}
