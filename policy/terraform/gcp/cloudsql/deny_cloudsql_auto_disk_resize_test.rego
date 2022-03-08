package terraform_gcp

import data.testing as t

test_not_deny_cloudsql_auto_disk_resize_as_string {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "disk_autoresize": "false"
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_auto_disk_resize, 1) with input as input
}

test_not_deny_cloudsql_auto_disk_resize {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "name": "test",
                    "settings": {
                        "disk_autoresize": false
                    }
                }
            }
        }
    }

    t.error_count(deny_cloudsql_auto_disk_resize, 1) with input as input
}

test_not_deny_cloudsql_auto_disk_resize_no_prop {
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

    t.no_errors(deny_cloudsql_auto_disk_resize) with input as input
}

test_not_deny_cloudsql_auto_disk_resize_when_exception {
    input := {
        "resource": {
            "google_sql_database_instance": {
                "test": {
                    "//": "TF_GCP_47",
                    "name": "test",
                    "settings": {
                        "disk_autoresize": "false"
                    }
                }
            }
        }
    }

    t.no_errors(deny_cloudsql_auto_disk_resize) with input as input
}
