package terraform_gcp

import data.terraform

test_not_deny_iam_policy_with_exclusions {
    input := {
        "data": {
            "google_iam_policy": {
                "p": {
                    "binding": [
                        {
                            "role": "roles/storage.admin",
                            "members": [
                                "group:test@domain.com",
                            ],
                        },
                        {
                            "//": "TF_GCP_04",
                            "role": "roles/storage.admin",
                            "members": [
                                "allAuthenticatedUsers",
                            ],
                        },
                    ],
                },
            },
        },
        "resource": {
            "google_storage_bucket": {
                "b": {
                    "name": "b",
                    "location": "EUROPE-WEST4",
                    "storage_class": "STANDARD",
                    "uniform_bucket_level_access": "true",
                },
            },
            "google_storage_bucket_iam_policy": {
                "b": {
                    "bucket": "${google_storage_bucket.b.name}",
                    "policy_data": "${data.google_iam_policy.p.policy_data}",
                },
            },
        },
    }

    not deny_iam_policy[sprintf("TF_GCP_04: public users (allUsers) not allowed for policy. More info: %s", [get_url(check04)])] with input as input
}

test_deny_iam_policy {
    input := {
        "data": {
            "google_iam_policy": {
                "p": {
                    "binding": [
                        {
                            "role": "roles/storage.admin",
                            "members": [
                                "allUsers",
                            ],
                        },
                    ],
                },
            },
        },
        "resource": {
            "google_storage_bucket": {
                "b": {
                    "name": "b",
                    "location": "EUROPE-WEST4",
                    "storage_class": "STANDARD",
                    "uniform_bucket_level_access": "true",
                },
            },
            "google_storage_bucket_iam_policy": {
                "b": {
                    "bucket": "${google_storage_bucket.b.name}",
                    "policy_data": "${data.google_iam_policy.p.policy_data}",
                },
            },
        },
    }

    deny_iam_policy with input as input
}


test_not_deny_iam_policy {
    input := {
        "data": {
            "google_iam_policy": {
                "p": {
                    "binding": [
                        {
                            "role": "roles/storage.admin",
                            "members": [
                                "group:test@domain.com",
                            ],
                        },
                    ],
                },
            },
        },
        "resource": {
            "google_storage_bucket": {
                "b": {
                    "name": "b",
                    "location": "EUROPE-WEST4",
                    "storage_class": "STANDARD",
                    "uniform_bucket_level_access": "true",
                },
            },
            "google_storage_bucket_iam_policy": {
                "b": {
                    "bucket": "${google_storage_bucket.b.name}",
                    "policy_data": "${data.google_iam_policy.p.policy_data}",
                },
            },
        },
    }

   not deny_iam_policy[sprintf("TF_GCP_04: public users (allUsers) not allowed for policy. More info: %s", [get_url(check04)])] with input as input
}
