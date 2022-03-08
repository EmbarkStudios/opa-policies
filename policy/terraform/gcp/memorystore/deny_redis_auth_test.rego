package terraform_gcp

import data.testing as t

test_deny_memorystore_redis_no_auth_no_prop {
    input := {
        "resource": {
            "google_redis_instance": {
                "test": {
                    "name": "test"
                }
            }
        }
    }

    t.error_count(deny_memorystore_redis_no_auth, 1) with input as input
}

test_deny_memorystore_redis_no_auth_false_string {
    input := {
        "resource": {
            "google_redis_instance": {
                "test": {
                    "name": "test",
                    "auth_enabled": "false"
                }
            }
        }
    }

    t.error_count(deny_memorystore_redis_no_auth, 1) with input as input
}

test_deny_memorystore_redis_no_auth_false_native {
    input := {
        "resource": {
            "google_redis_instance": {
                "test": {
                    "name": "test",
                    "auth_enabled": false
                }
            }
        }
    }

    t.error_count(deny_memorystore_redis_no_auth, 1) with input as input
}

test_not_deny_memorystore_redis_no_auth_with_exception {
    input := {
        "resource": {
            "google_redis_instance": {
                "test": {
                    "//": "TF_GCP_49",
                    "name": "test",
                    "auth_enabled": "false"
                }
            }
        }
    }

    t.no_errors(deny_memorystore_redis_no_auth) with input as input
}
