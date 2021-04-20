package terraform_gcp

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

    not deny_gke_alias_ip["TF_GCP_05: alias ip not enabled for test"] with input as input
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

    not deny_gke_alias_ip["TF_GCP_05: alias ip not enabled for test"] with input as input
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

    deny_gke_alias_ip with input as input
}
