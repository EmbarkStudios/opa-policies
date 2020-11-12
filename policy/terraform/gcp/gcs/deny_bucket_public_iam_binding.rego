package terraform_gcp

import data.terraform

check03 := "TF_GCP_03"

# DENY(TF_GCP_03)
exception[k] {
    input.resource.google_storage_bucket_iam_binding
    binding := input.resource.google_storage_bucket_iam_binding[k]
    checks := split(binding["//"], ",")
    contains_element(checks, check02)
}

deny_public_iam_binding[msg] {
    input.resource.google_storage_bucket_iam_binding
    binding := input.resource.google_storage_bucket_iam_binding[k]

    not exception[k]
    binding.members[member] == blacklisted_users[user]

    msg = sprintf("%s: public users (%s) not allowed for bucket: %s", [check03, binding.members[member], binding.bucket])
}
