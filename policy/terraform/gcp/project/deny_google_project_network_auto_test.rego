package terraform_gcp

test_not_deny_project_auto_created_network_with_exclusions {
    input := {
        "resource": {
            "google_project": {
                "p": {
                    "//": "TF_GCP_06",
                    "name": "p",
                    "project_id": "project_id"
                },
            },
        },
    }

    not deny_project_auto_created_network["TF_GCP_06: auto created networks are not allowed for project p"] with input as input
}

test_deny_project_auto_created_network {
    input := {
        "resource": {
            "google_project": {
                "p": {
                    "name": "p",
                    "project_id": "project_id"
                },
            },
        },
    }

    deny_project_auto_created_network with input as input
}


test_not_deny_project_auto_created_network {
    input := {
        "resource": {
            "google_project": {
                "p": {
                    "name": "p",
                    "project_id": "project_id",
                    "auto_created_network": false,
                },
            },
        },
    }

   not deny_project_auto_created_network["TF_GCP_06: auto created networks are not allowed for project p"] with input as input
}

test_not_deny_project_auto_created_network_string {
    input := {
        "resource": {
            "google_project": {
                "p": {
                    "name": "p",
                    "project_id": "project_id",
                    "auto_created_network": "false",
                },
            },
        },
    }

   not deny_project_auto_created_network["TF_GCP_06: auto created networks are not allowed for project p"] with input as input
}
