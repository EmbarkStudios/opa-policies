package terraform_gcp

import data.terraform

test_not_deny_autoupgrade {
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
        }
    }

    t.no_errors(deny_gke_autoupgrade_disabled) with input as input
}

test_not_deny_autoupgrade_exclusions {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "//": "TF_GCP_19" 
                }
            }
        }
    }

    t.no_errors(deny_gke_autoupgrade_disabled) with input as input
}

test_deny_missing_autoupgrade_config {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "management": {}
                }           
            }
        }
    }

    t.error_count(deny_gke_autoupgrade_disabled, 1) with input as input
}

test_deny_autoupgrade_false {
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
        }
    }

    t.error_count(deny_gke_autoupgrade_disabled, 1) with input as input
}

test_deny_autoupgrade_false_string {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "management": {
                        "auto_upgrade": "false"           
                    }
                }
            }
        }
    }

    t.error_count(deny_gke_autoupgrade_disabled, 1) with input as input
}
