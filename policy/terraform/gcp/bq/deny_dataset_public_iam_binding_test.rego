package terraform_gcp

import data.terraform

test_deny_dataset_public_iam_binding {
    input := {
        "resource": {
            "google_bigquery_dataset_iam_binding": {
                "public-member": {
                    "dataset_id": "ds",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["allUsers", "group:test@embark.dev"]
                }
            }
        }
    }

    deny_dataset_public_iam_binding with input as input
}

test_not_deny_dataset_public_iam_binding_when_exception {
    input := {
        "resource": {
            "google_bigquery_dataset_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_09",
                    "dataset_id": "ds",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["allUsers", "group:test@embark.dev"]
                }
            }
        }
    }

    not deny_dataset_public_iam_binding[sprintf("TF_GCP_09: public users (%s) not allowed for dataset: ds. More info: %s", [get_url(check09)])] with input as input
}

test_deny_dataset_public_iam_binding_more_members {
    input := {
        "resource": {
            "google_bigquery_dataset_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_09",
                    "dataset_id": "ds1",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["allUsers", "group:test@embark.dev"]
                },
                "should be blocked": {
                    "dataset_id": "ds2",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["allUsers", "group:test@embark.dev"]
                },
                "should not be blocked": {
                    "dataset_id": "ds3",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["group:test@embark.dev"]
                }
            }
        }
    }

    deny_dataset_public_iam_binding with input as input
}
