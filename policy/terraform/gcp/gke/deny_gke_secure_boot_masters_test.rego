package terraform_gcp

import data.testing as t

test_not_deny_secureboot_masters {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "node_config": {
                        "shielded_instance_config": {
                          "enable_secure_boot": true
                        }
                    }
                }
            }
        }
    }

    t.no_errors(deny_gke_secureboot_masters_disabled) with input as input
}

test_not_deny_secureboot_masters_exclusions {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "//": "TF_GCP_23" 
                }
            }
        }
    }

    t.no_errors(deny_gke_secureboot_masters_disabled) with input as input
}

test_deny_missing_secureboot_masters_config {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "node_config": {
                        "shielded_instance_config": {}
                    }
                }           
            }
        }
    }

    t.error_count(deny_gke_secureboot_masters_disabled, 1) with input as input
}

test_deny_secureboot_masters_false {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "node_config": {
                        "shielded_instance_config": {
                          "enable_secure_boot": false
                        }
                    }
                }
            }
        }
    }

    t.error_count(deny_gke_secureboot_masters_disabled, 1) with input as input
}

test_deny_secureboot_masters_false_string {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "node_config": {
                        "shielded_instance_config": {
                          "enable_secure_boot": "false"
                        }
                    }
                }
            }
        }
    }

    t.error_count(deny_gke_secureboot_masters_disabled, 1) with input as input
}
