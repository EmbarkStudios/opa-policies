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

    deny_bucket_public_iam_member with input as input
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

    not deny_bucket_public_iam_member[sprintf("TF_GCP_02: public users not allowed for bucket: embark-public. More info: %s", [get_url(check02)])] with input as input
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

    deny_bucket_public_iam_member with input as input
}
