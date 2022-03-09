package terraform_gcp

import data.testing as t

test_not_deny_cloudsql_postgres_flags {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "POSTGRES_13",
                    "settings": {
                        "database_flags": [
                            {"name": "log_checkpoints", "value": "on"},
                            {"name": "log_connections", "value": "on"},
                            {"name": "log_disconnections", "value": "on"},
                            {"name": "log_lock_waits", "value": "on"}
                        ]
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_postgres_flags) with input as input
}

test_not_deny_cloudsql_postgres_flags {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "SQLSERVER_2019_STANDARD",
                    "settings": {}
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_postgres_flags) with input as input
}

test_not_deny_cloudsql_postgres_flags_additional_flag {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "POSTGRES_13",
                    "settings": {
                        "database_flags": [
                            {"name": "log_disconnections", "value": "on"},
                            {"name": "log_connections", "value": "on"},
                            {"name": "log_checkpoints", "value": "on"},
                            {"name": "log_lock_waits", "value": "on"},
                            {"name": "a_flag", "value": "on"}
                        ]
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_postgres_flags) with input as input
}

test_deny_cloudsql_postgres_flags_missing {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "POSTGRES_13",
                    "settings": {
                        "database_flags": [
                            {"name": "log_checkpoints", "value": "on"},
                            {"name": "log_connections", "value": "on"},
                            {"name": "log_disconnections", "value": "on"},
                        ]
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_postgres_flags, 1) with input as input
}

test_not_deny_cloudsql_postgres_flags_missing {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "//":"TF_GCP_54",
                    "name": "test",
                    "database_version": "POSTGRES_13",
                    "settings": {
                        "database_flags": [
                            {"name": "log_checkpoints", "value": "on"},
                            {"name": "log_connections", "value": "on"},
                            {"name": "log_disconnections", "value": "on"},
                        ]
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_postgres_flags) with input as input
}
