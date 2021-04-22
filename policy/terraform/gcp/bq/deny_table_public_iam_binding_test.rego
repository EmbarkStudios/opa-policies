package terraform_gcp

import data.terraform

test_deny_table_public_iam_binding {
    input := {
        "resource": {
            "google_bigquery_table_iam_binding": {
                "public-member": {
                    "dataset_id": "ds",
                    "table_id": "x",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["allUsers", "group:test@embark.dev"]
                }
            }
        }
    }

    deny_table_public_iam_binding with input as input
}

test_not_deny_table_public_iam_binding_when_exception {
    input := {
        "resource": {
            "google_bigquery_table_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_10",
                    "dataset_id": "ds",
                    "table_id": "x",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["allUsers", "group:test@embark.dev"]
                }
            }
        }
    }

    not deny_table_public_iam_binding[sprintf("TF_GCP_10: public users (%s) not allowed for dataset: ds, table: x. More info: %s", [get_url(check10)])] with input as input
}

test_deny_table_public_iam_binding_more_members {
    input := {
        "resource": {
            "google_bigquery_table_iam_binding": {
                "public-member": {
                    "//": "TF_GCP_10",
                    "dataset_id": "ds1",
                    "table_id": "x",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["allUsers", "group:test@embark.dev"]
                },
                "should be blocked": {
                    "dataset_id": "ds2",
                    "table_id": "x",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["allUsers", "group:test@embark.dev"]
                },
                "should not be blocked": {
                    "dataset_id": "ds3",
                    "table_id": "x",
                    "role": "roles/bigquery.dataEditor",
                    "members": ["group:test@embark.dev"]
                }
            }
        }
    }

    deny_table_public_iam_binding with input as input
}
