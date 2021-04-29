package terraform_gcp

import data.testing as t

test_not_deny_remove_default_node_pool {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "remove_default_node_pool": true
                }
            }
        }
    }

    t.no_errors(deny_gke_remove_default_node_pool) with input as input
}

test_not_deny_remove_default_node_pool_exclusions {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "//": "TF_GCP_29" 
                }
            }
        }
    }

    t.no_errors(deny_gke_remove_default_node_pool) with input as input
}

test_deny_missing_remove_default_node_pool_config {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "remove_default_node_pool": ""
                }           
            }
        }
    }

    t.error_count(deny_gke_remove_default_node_pool, 1) with input as input
}

test_deny_remove_default_node_pool_false {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "remove_default_node_pool": false
                }
            }
        }
    }

    t.error_count(deny_gke_remove_default_node_pool, 1) with input as input
}

test_deny_remove_default_node_pool_false_string {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "remove_default_node_pool": "false"
                }
            }
        }
    }

    t.error_count(deny_gke_remove_default_node_pool, 1) with input as input
}
