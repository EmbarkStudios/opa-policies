package terraform_gcp

import data.testing as t

test_not_deny_autorepair {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster":"cluster1",
                    "name": "test",
                    "location": "us-central1",
                    "management": {
                        "auto_repair": true            
                    }
                }
            }
        }
    }

    t.no_errors(deny_gke_autorepair_disabled) with input as input
}

test_not_deny_autorepair_exclusions {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster":"cluster1",
                    "name": "test",
                    "location": "us-central1",
                    "//": "TF_GCP_19" 
                }
            }
        }
    }

    t.no_errors(deny_gke_autorepair_disabled) with input as input
}

test_deny_missing_autorepair_config {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster":"cluster1",
                    "name": "test",
                    "location": "us-central1",
                    "management": {}
                }           
            }
        }
    }

    t.error_count(deny_gke_autorepair_disabled, 1) with input as input
}

test_deny_autorepair_false {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster":"cluster1",
                    "name": "test",
                    "location": "us-central1",
                    "management": {
                        "auto_repair": false           
                    }
                }
            }
        }
    }

    t.error_count(deny_gke_autorepair_disabled, 1) with input as input
}

test_deny_autorepair_false_string {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "cluster":"cluster1",
                    "name": "test",
                    "location": "us-central1",
                    "management": {
                        "auto_repair": "false"           
                    }
                }
            }
        }
    }

    t.error_count(deny_gke_autorepair_disabled, 1) with input as input
}
