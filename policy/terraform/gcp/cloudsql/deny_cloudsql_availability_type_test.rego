package terraform_gcp

import data.testing as t

test_not_deny_cloudsql_availability_type {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "availability_type": "REGIONAL"
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_availability_type) with input as input
}

test_deny_cloudsql_availability_type_without_conf {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {}
                }
            }
        }
    }

    t.error_count(deny_cloudsql_availability_type, 1) with input as input
}

test_deny_cloudsql_availability_type_zonal {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "availability_type": "ZONAL"
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_availability_type, 1) with input as input
}

test_not_deny_cloudsql_availability_type_zonal_with_exception {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "//": "TF_GCP_48",
                    "name": "test",
                    "settings": {
                        "availability_type": "ZONAL"
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_availability_type) with input as input
}
