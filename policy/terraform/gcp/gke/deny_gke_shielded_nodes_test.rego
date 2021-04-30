package terraform_gcp

import data.testing as t

test_not_deny_shielded_nodes {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "enable_shielded_nodes": true
                }
            }
        }
    }

    t.no_errors(deny_gke_shielded_nodes) with input as input
}

test_not_deny_shielded_nodes_exclusions {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "//": "TF_GCP_34" 
                }
            }
        }
    }

    t.no_errors(deny_gke_shielded_nodes) with input as input
}

test_deny_shielded_nodes_false {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "enable_shielded_nodes": false
                }
            }
        }
    }

    t.error_count(deny_gke_shielded_nodes, 1) with input as input
}

test_deny_shielded_nodes_false_string {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "enable_shielded_nodes": "false"
                }
            }
        }
    }

    t.error_count(deny_gke_shielded_nodes, 1) with input as input
}
