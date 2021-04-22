package terraform_gcp

import data.terraform

test_deny_compute_firewall_unrestricted {
    input := {
        "resource": {
            "google_compute_firewall": {
                "f1": {
                    "name": "f1",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": {
                        "ports":["22", "5432"]
                    }
                }
            }
        }
    }

    deny_compute_firewall_unrestricted with input as input
}

test_not_deny_compute_firewall_unrestricted_when_no_allow {
    input := {
        "resource": {
            "google_compute_firewall": {
                "f1": {
                    "name": "f1",
                    "source_ranges": ["0.0.0.0/0"],
                    "deny": {
                        "ports":["22", "5432"]
                    }
                }
            }
        }
    }

    not deny_compute_firewall_unrestricted[sprintf("TF_GCP_14: firewall rule: f1 is unrestricted (0.0.0.0/0). More info: %s", [get_url(check14)])] with input as input
}

test_not_deny_compute_firewall_unrestricted_when_exception {
    input := {
        "resource": {
            "google_compute_firewall": {
                "p1": {
                    "//": "TF_GCP_14",
                    "name": "f1",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": {
                        "ports":["22", "5432"]
                    }
                }
            }
        }
    }

    not deny_compute_firewall_unrestricted[sprintf("TF_GCP_14: firewall rule: f1 is unrestricted (0.0.0.0/0). More info: %s", [get_url(check14)])] with input as input
}

test_deny_compute_firewall_unrestricted_multiple {
    input := {
        "resource": {
            "google_compute_firewall": {
                "f1": {
                    "//": "TF_GCP_14",
                    "name": "f1",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": {
                        "ports":["22", "5432"]
                    }
                },
                "f2": {
                   	"name": "f2",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": {
                        "ports":["22", "5432"]
                    }
                },
                "f3": {
                    "name": "f3",
                    "source_ranges": ["35.191.0.0/16"],
                    "allow": {
                        "ports":["22", "5432"]
                    }
                }
            }
        }
    }

    deny_compute_firewall_unrestricted with input as input
}
