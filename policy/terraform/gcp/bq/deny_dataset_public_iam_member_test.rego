package terraform_gcp

import data.testing as t

test_deny_dataset_public_iam_member {
    input := {
        "resource": {
            "google_bigquery_dataset_iam_member": {
                "public-member": {
                    "dataset_id": "ds",
                    "role": "roles/bigquery.dataEditor",
                    "member": "allUsers"
                }
            }
        }
    }

    t.error_count(deny_dataset_public_iam_member, 1) with input as input
}

test_not_deny_dataset_public_iam_member_when_exception {
    input := {
        "resource": {
            "google_bigquery_dataset_iam_member": {
                "public-member": {
                    "//": "TF_GCP_07",
                    "dataset_id": "ds",
                    "role": "roles/bigquery.dataEditor",
                    "member": "allUsers"
                }
            }
        }
    }

    t.no_errors(deny_dataset_public_iam_member) with input as input
}

test_deny_dataset_public_iam_member_more_members {
    input := {
        "resource": {
            "google_bigquery_dataset_iam_member": {
                "public-member": {
                    "//": "TF_GCP_07",
                    "dataset_id": "ds",
                    "role": "roles/bigquery.dataEditor",
                    "member": "allUsers"
                },
                "should be blocked": {
                    "dataset_id": "ds2",
                    "role": "roles/bigquery.dataEditor",
                    "member": "allUsers"
                }
            }
        }
    }

    t.error_count(deny_dataset_public_iam_member, 1) with input as input
}
