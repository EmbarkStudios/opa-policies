package terraform_gcp

import data.testing as t

test_not_deny_cloudsql_no_backup {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "backup_configuration": {
                            "enabled": true
                        }
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_no_backup) with input as input
}

test_deny_cloudsql_no_backup_without_conf {
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

    t.error_count(deny_cloudsql_no_backup, 1) with input as input
}

test_not_deny_cloudsql_no_backup_as_string {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "backup_configuration": {
                            "enabled": "true"
                        }
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_no_backup) with input as input
}

test_not_deny_cloudsql_no_backup_no_prop {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "backup_configuration": {
                            "backup_retention_settings": {
                                "retained_backups": 14
                            }
                        }
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_no_backup) with input as input
}

test_not_deny_cloudsql_no_backup_when_exception {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "//": "TF_GCP_46",
                    "name": "test",
                    "settings": {
                        "backup_configuration": {
                            "enabled": "false",
                        }
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_no_backup) with input as input
}

test_deny_deny_cloudsql_no_backup_with_string {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "backup_configuration": {
                            "enabled": "false",
                        }
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_no_backup, 1) with input as input
}

test_deny_deny_cloudsql_no_backup {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "backup_configuration": {
                            "enabled": false,
                        }
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_no_backup, 1) with input as input
}
