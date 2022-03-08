package terraform_gcp

import data.testing as t

test_deny_iap_no_host_condition {
    input := {
        "resource": {
            "google_iap_web_iam_member": {
                "public-member": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "group:test@test.com"
                }
            }
        }
    }

    t.error_count(deny_iap_no_host_condition, 1) with input as input
}

test_not_iap_no_host_condition_when_exception {
    input := {
        "resource": {
            "google_iap_web_iam_member": {
                "public-member": {
                    "//": "TF_GCP_43",
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "group:test@test.com",
                    "condition": {
                        "expression": "request.time < timestamp(\"2020-01-01T00:00:00Z\")"
                    },
                }
            }
        }
    }

    t.no_errors(deny_iap_no_host_condition) with input as input
}

test_deny_iap_no_host_multiple {
    input := {
        "resource": {
            "google_iap_web_iam_member": {
                "public-member": {
                    "//": "TF_GCP_43",
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "test@test.com",
                    "condition": {
                        "expression": "request.time < timestamp(\"2020-01-01T00:00:00Z\")"
                    }
                },
                "should be blocked": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "test@test.com",
                    "condition": {
                        "expression": "request.time < timestamp(\"2020-01-01T00:00:00Z\")"
                    }
                }
            }
        }
    }

    t.error_count(deny_iap_no_host_condition, 1) with input as input
}

test_not_deny_iap_with_condition {
    input := {
        "resource": {
            "google_iap_web_iam_member": {
                "public-member": {
                    "role": "roles/iap.httpsResourceAccessor",
                    "member": "test@test.com",
                    "condition": {
                        "expression": "request.host == \"google.com\""
                    },
                },
            }
        }
    }

    t.no_errors(deny_iap_no_host_condition) with input as input
}
