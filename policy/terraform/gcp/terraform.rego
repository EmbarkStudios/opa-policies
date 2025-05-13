package terraform_gcp

import rego.v1

import data.lib as l

buckets contains bucket if {
	bucket = input.resource.google_storage_bucket[bucket]
}

blacklisted_users := ["allUsers", "allAuthenticatedUsers"]

default_service_account_regexp := ".*-compute@developer.gserviceaccount.com|.*@appspot.gserviceaccount.com|.*@cloudbuild.gserviceaccount.com"

impersonation_roles := ["roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"]

make_exception(check, obj) if {
	checks := split(obj["//"], ",")
	l.contains_element(checks, check)
}
