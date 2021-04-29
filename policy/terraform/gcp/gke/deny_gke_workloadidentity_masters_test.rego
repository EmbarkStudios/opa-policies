package terraform_gcp

import data.testing as t

test_not_deny_workloadidentity_masters {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "node_config": {
                        "workload_metadata_config": {
                          "node_metadata": node_metadata
                        }
                    }
                }
            }
        }
    }

    t.no_errors(deny_gke_workloadidentity_masters_disabled) with input as input
}

test_not_deny_workloadidentity_masters_exclusions {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "//": "TF_GCP_24" 
                }
            }
        }
    }

    t.no_errors(deny_gke_workloadidentity_masters_disabled) with input as input
}

test_deny_missing_workloadidentity_masters_config {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "node_config": {
                        "workload_metadata_config": {}
                    }
                }           
            }
        }
    }

    t.error_count(deny_gke_workloadidentity_masters_disabled, 1) with input as input
}

test_deny_workloadidentity_masters_unspecified {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "node_config": {
                        "workload_metadata_config": {
                          "node_metadata": "UNSPECIFIED"
                        }
                    }
                }
            }
        }
    }

    t.error_count(deny_gke_workloadidentity_masters_disabled, 1) with input as input
}

