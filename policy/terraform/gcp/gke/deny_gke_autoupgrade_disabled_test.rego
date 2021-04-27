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

<<<<<<< HEAD
    error_count(deny_gke_autoupgrade_disabled, 1) with input as input
=======
    no_errors(deny_gke_autoupgrade_disabled) with input as input
>>>>>>> 8abee4810519a8d728d6de9946b6cdd73e8b91e8
}

test_deny_google_container_node_pool {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                }           
            }
        },
    }

<<<<<<< HEAD
    error_count(deny_gke_autoupgrade_disabled, 1) with input as input
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

    error_count(deny_gke_autoupgrade_disabled, 1) with input as input
}

test_deny_google_container_node_pool {
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
        },
    }

    error_count(deny_gke_autoupgrade_disabled, 1) with input as input
}
=======
    deny_gke_autoupgrade_disabled with input as input
}
>>>>>>> 8abee4810519a8d728d6de9946b6cdd73e8b91e8
