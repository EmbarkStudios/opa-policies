package terraform_gcp

import data.terraform

test_deny_table_public_iam_member {
    input := {
        "resource": {
            "google_bigquery_table_iam_member": {
                "public-member": {
                    "dataset_id": "ds",
                    "table_id": "t",
                    "role": "roles/bigquery.dataEditor",
                    "member": "allUsers"
                }
            }
        }
    }

    error_count(deny_table_public_iam_member, 1) with input as input
}

test_not_deny_table_public_iam_member_when_exception {
    input := {
        "resource": {
            "google_bigquery_table_iam_member": {
                "public-member": {
                    "//": "TF_GCP_08",
                    "dataset_id": "ds",
                    "table_id": "t",
                    "role": "roles/bigquery.dataEditor",
                    "member": "allUsers"
                }
            }
        }
    }

    no_errors(deny_table_public_iam_member) with input as input
}

test_deny_table_public_iam_member_more_members {
    input := {
        "resource": {
            "google_bigquery_table_iam_member": {
                "public-member": {
                    "//": "TF_GCP_08",
                    "dataset_id": "ds",
                    "table_id": "t",
                    "role": "roles/bigquery.dataEditor",
                    "member": "allUsers"
                },
                "should be blocked": {
                    "dataset_id": "ds2",
                    "table_id": "t",
                    "role": "roles/bigquery.dataEditor",
                    "member": "allUsers"
                }
            }
        }
    }

    error_count(deny_table_public_iam_member, 1) with input as input
}
