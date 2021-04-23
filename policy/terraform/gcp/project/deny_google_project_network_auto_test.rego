package terraform_gcp

import data.terraform

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

    count(deny_project_auto_created_network) == 0 with input as input
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

test_deny_project_auto_created_network_with_property {
    input := {
        "resource": {
            "google_project": {
                "p": {
                    "name": "p",
                    "project_id": "project_id",
                    "auto_create_network": true
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
                    "auto_create_network": false,
                },
            },
        },
    }

   count(deny_project_auto_created_network) == 0 with input as input
}

test_not_deny_project_auto_created_network_string {
    input := {
        "resource": {
            "google_project": {
                "p": {
                    "name": "p",
                    "project_id": "project_id",
                    "auto_create_network": "false",
                },
            },
        },
    }

   count(deny_project_auto_created_network) == 0 with input as input
}
