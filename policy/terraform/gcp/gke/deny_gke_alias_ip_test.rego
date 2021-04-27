package terraform_gcp

import data.testing as t

test_not_deny_google_container_cluster {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "ip_allocation_policy": {
                        "cluster_secondary_range_name": "pod-range",
                        "services_secondary_range_name": "service-range"
                    }
                }
            }
        },
    }

    t.no_errors(deny_gke_alias_ip) with input as input
}

test_not_deny_google_container_cluster_with_exclusions {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                    "//": "TF_GCP_05" 
                }
            }
        },
    }

    t.no_errors(deny_gke_alias_ip) with input as input
}

test_deny_google_container_cluster {
    input := {
        "resource": {
            "google_container_cluster": {
                "test": {
                    "name": "test",
                    "location": "us-central1",
                }
            }
        },
    }

    t.error_count(deny_gke_alias_ip, 1) with input as input
}
