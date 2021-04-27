package terraform_gcp

import data.terraform

test_deny_compute_weak_ssl_policy {
    input := {
        "resource": {
            "google_compute_ssl_policy": {
                "p1": {
                    "name": "p1",
                    "profile": "COMPATIBLE",
                }
            }
        }
    }

    error_count(deny_compute_weak_ssl_policy, 1) with input as input
}

test_not_deny_compute_weak_ssl_policy_when_exception {
    input := {
        "resource": {
            "google_compute_ssl_policy": {
                "p1": {
                    "//": "TF_GCP_11",
                    "name": "p1",
                    "profile": "COMPATIBLE"
                }
            }
        }
    }

    no_errors(deny_compute_weak_ssl_policy) with input as input
}

test_deny_compute_weak_ssl_policy_multiple {
    input := {
        "resource": {
            "google_compute_ssl_policy": {
                "compatible": {
                    "//": "TF_GCP_11",
                    "name": "p1",
                    "profile": "COMPATIBLE"
                },
                "compatible2": {
                   	"name": "p2",
                    "profile": "COMPATIBLE"
                },
                "modern": {
                    "name": "p3",
                    "profile": "MODERN"
                },
                "restricted": {
                    "name": "p3",
                    "profile": "RESTRICTED"
                }
            }
        }
    }

    error_count(deny_compute_weak_ssl_policy, 1) with input as input
}
