package terraform_gcp

import data.testing as t

test_not_deny_workloadidentity_nodes {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster": "cluster1",              
                    "name": "test",
                    "node_config": {
                        "workload_metadata_config": {
                          "node_metadata": "GKE_METADATA_SERVER"
                        }
                    }
                }
            }
        }
    }

    t.no_errors(deny_gke_workloadidentity_nodes_disabled) with input as input
}

test_not_deny_workloadidentity_nodes_exclusions {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster": "cluster1",                    
                    "name": "test",
                    "//": "TF_GCP_25" 
                }
            }
        }
    }

    t.no_errors(deny_gke_workloadidentity_nodes_disabled) with input as input
}

test_deny_missing_workloadidentity_nodes_config {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster": "cluster1",
                    "name": "test",
                    "node_config": {
                        "workload_metadata_config": {}
                    }
                }           
            }
        }
    }

    t.error_count(deny_gke_workloadidentity_nodes_disabled, 1) with input as input
}

test_deny_workloadidentity_nodes_unspecified {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster": "cluster1",
                    "name": "test",
                    "node_config": {
                        "workload_metadata_config": {
                          "node_metadata": "UNSPECIFIED"
                        }
                    }
                }
            }
        }
    }

    t.error_count(deny_gke_workloadidentity_nodes_disabled, 1) with input as input
}

