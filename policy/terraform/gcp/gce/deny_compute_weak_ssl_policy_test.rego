package terraform_gcp

test_deny_compute_weak_ssl_policy {
    input := {
        "resource": {
            "google_compute_ssl_policy": {
                "p1": {
                    "name": "p1",
                    "profile": "MODERN",
                }
            }
        }
    }

    deny_compute_weak_ssl_policy with input as input
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

    not deny_compute_weak_ssl_policy["TF_GCP_11: ssl policy: p1 has a weak profile: COMPATIBLE"] with input as input
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
                "restricted": {
                    "name": "p3",
                    "profile": "RESTRICTED"
                }
            }
        }
    }

    deny_compute_weak_ssl_policy with input as input
}
