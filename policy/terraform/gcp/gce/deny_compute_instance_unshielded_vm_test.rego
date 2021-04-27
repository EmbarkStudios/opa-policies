package terraform_gcp

import data.terraform

test_deny_missing_shielded_instance_config {
    input := {
        "resource": {
            "google_compute_instance": {
                "i1": {
                    "name": "deny_me"
                }
            }
        }
    }

    error_count(deny_compute_instance_unshielded_vm, 1) with input as input
}

test_deny_shielded_instance_config_without_secure_boot_enabled {
    input := {
        "resource": {
            "google_compute_instance": {
                "i1": {
                    "name": "deny_me",
                    "shielded_instance_config": {}
                }
            }
        }
    }

    error_count(deny_compute_instance_unshielded_vm, 1) with input as input
}

test_deny_shielded_instance_config_with_secure_boot_disabled {
    input := {
        "resource": {
            "google_compute_instance": {
                "i1": {
                    "name": "deny_me",
                    "shielded_instance_config": {
                        "secure_boot_enabled": false
                    }
                }
            }
        }
    }

    error_count(deny_compute_instance_unshielded_vm, 1) with input as input
}

test_deny_shielded_instance_config_with_secure_boot_disabled_string {
    input := {
        "resource": {
            "google_compute_instance": {
                "i1": {
                    "name": "deny_me",
                    "shielded_instance_config": {
                        "secure_boot_enabled": "false"
                    }
                }
            }
        }
    }

    error_count(deny_compute_instance_unshielded_vm, 1) with input as input
}

test_not_deny_with_exception {
    input := {
        "resource": {
            "google_compute_instance": {
                "i1": {
                    "//": "TF_GCP_20",
                    "name": "allow_me",
                    "shielded_instance_config": {
                        "secure_boot_enabled": false
                    }
                },
                "i2": {
                    "//": "TF_GCP_20",
                    "name": "allow_me",
                    "shielded_instance_config": {}
                },
                "i3": {
                    "//": "TF_GCP_20",
                    "name": "allow_me",
                }
            }
        }
    }

    no_errors(deny_compute_instance_unshielded_vm) with input as input
}

test_not_deny_secure_boot_enabled {
    input := {
        "resource": {
            "google_compute_instance": {
                "i1": {
                    "name": "allow_me",
                    "shielded_instance_config": {
                        "secure_boot_enabled": true
                    }
                }
            },
            "google_compute_instance": {
                "i2": {
                    "name": "allow_me",
                    "shielded_instance_config": {
                        "secure_boot_enabled": "true",
                    }
                }
            }
        }
    }

    no_errors(deny_compute_instance_unshielded_vm) with input as input
}
