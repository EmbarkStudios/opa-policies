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

    deny_table_public_iam_member with input as input
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

    not deny_table_public_iam_member[sprintf("TF_GCP_08: public users not allowed for dataset: ds, table: t. More info: %s", [get_url(check08)])] with input as input
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

    deny_table_public_iam_member with input as input
}
