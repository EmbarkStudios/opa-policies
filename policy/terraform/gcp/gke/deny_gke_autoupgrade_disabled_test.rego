package terraform_gcp

import data.terraform

test_not_deny_google_container_node_pool {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "management": {
                        "auto_upgrade": true            
                    }
                }
            }
        },
    }

    no_errors(deny_gke_autoupgrade_disabled) with input as input
}

test_not_deny_google_container_node_pool_with_exclusions {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "//": "TF_GCP_19" 
                }
            }
        },
    }

    no_errors(deny_gke_autoupgrade_disabled) with input as input
}

test_deny_google_container_node_pool {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "management": {
                      "auto_upgrade": false
                    }
                }           
            }
        },
    }

    deny_gke_autoupgrade_disabled with input as input
}
