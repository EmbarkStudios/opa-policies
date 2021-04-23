package terraform_gcp

import data.terraform

test_deny_uniform_level_access_exception {
    input := {
        "resource": {
            "google_storage_bucket": {
                "b3": {
                    "name": "b3",
                    "//": "TF_GCP_01",
                    "uniform_bucket_level_access": false,
                    "location": "eu",
                    "storage_class": "STANDARD"
                }
            }
        }
    }

    no_errors(deny_non_uniform_level_access) with input as input
}

test_deny_uniform_level_access {
    input := {
        "resource": {
            "google_storage_bucket": {
                "b1": {
                    "name": "b1",
                    "uniform_bucket_level_access": true,
                    "location": "eu",
                    "storage_class": "STANDARD"
                },
                "b2": {
                    "name": "b2",
                    "uniform_bucket_level_access": "false",
                    "location": "eu",
                    "storage_class": "STANDARD"
                },
            }
        }
    }

    deny_non_uniform_level_access with input as input
}

test_deny_uniform_level_access_all {
    input := {
        "resource": {
            "google_storage_bucket": {
                "b1": {
                    "name": "b1",
                    "uniform_bucket_level_access": true,
                    "location": "eu",
                    "storage_class": "STANDARD"
                },
                "b2": {
                    "name": "b2",
                    "uniform_bucket_level_access": false,
                    "location": "eu",
                    "storage_class": "STANDARD"
                },
                "b3": {
                    "name": "b3",
                    "//": "TF_GCP_01",
                    "uniform_bucket_level_access": false,
                    "location": "eu",
                    "storage_class": "STANDARD"
                }
            }
        }
    }

    deny_non_uniform_level_access with input as input
}

