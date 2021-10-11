package terraform_gcp

import data.testing as t

test_not_deny_imagetype {
    input := {
        "resource": {
            "google_container_node_pool": {
                "cos": {
                    "name": "cos",
                    "cluster": "cluster1",
                    "location": "us-central1",
                    "node_config": {
                        "image_type": "cos",
                    }
                },
                "cos_containerd": {
                    "name": "cos_containerd",
                    "cluster": "cluster1",
                    "location": "us-central1",
                    "node_config": {
                        "image_type": "cos_containerd",
                    }
                },
                "test_case_insensitive": {
                    "name": "test_case_insensitive",
                    "cluster": "cluster1",
                    "location": "us-central1",
                    "node_config": {
                        "image_type": "cOs_CoNtAiNeRd",
                    }
                }
            }
        }
    }

    t.no_errors(deny_gke_imagetype) with input as input
}

test_not_deny_imagetype_exclusions {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "cluster": "cluster1",
                    "location": "us-central1",
                    "//": "TF_GCP_27" 
                }
            }
        }
    }

    t.no_errors(deny_gke_imagetype) with input as input
}

test_deny_missing_imagetype_config {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "cluster": "cluster1",                    
                    "location": "us-central1",
                    "node_config": {
                        "image_type": {}
                    }
                }           
            }
        }
    }

    t.error_count(deny_gke_imagetype, 1) with input as input
}

test_deny_imagetype_wrong {
    input := {
        "resource": {
            "google_container_node_pool": {
                "test": {
                    "name": "test",
                    "cluster": "cluster1",
                    "location": "us-central1",
                    "node_config": {
                        "image_type": "UBUNTU"
                    }
                }
            }
        }
    }

    t.error_count(deny_gke_imagetype, 1) with input as input
}

