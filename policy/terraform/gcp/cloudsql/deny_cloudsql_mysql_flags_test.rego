package terraform_gcp

import data.testing as t

test_not_deny_cloudsql_mysql_flags {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "MYSQL_8_0",
                    "settings": {
                        "database_flags": [
                            {"name": "local_infile", "value": "off"}
                        ]
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_mysql_flags) with input as input
}

test_deny_cloudsql_mysql_flags_empty {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "MYSQL_8_0",
                    "settings": {
                        "database_flags": []
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_mysql_flags, 1) with input as input
}

test_deny_cloudsql_mysql_flags_no_prop {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "MYSQL_8_0",
                    "settings": {
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_mysql_flags, 1) with input as input
}


test_not_deny_cloudsql_mysql_flags_when_exception {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "MYSQL_8_0",
                    "//": "TF_GCP_53",
                    "settings": {
                        "database_flags": []
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_mysql_flags) with input as input
}

test_deny_cloudsql_mysql_flags_wrong_flag {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "MYSQL_8_0",
                    "settings": {
                        "database_flags": [
                            {"name": "not_existing", "value": "off"}
                        ]
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_mysql_flags, 1) with input as input
}

test_not_deny_cloudsql_mysql_flags_multiple {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "database_version": "MYSQL_8_0",
                    "settings": {
                        "database_flags": [
                            {"name": "local_infile", "value": "off"},
                            {"name": "not_existing", "value": "off"}
                        ]
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_mysql_flags) with input as input
}
