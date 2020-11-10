package terraform_gcp

import data.terraform

check02 := "TF_GCP_02"

# DENY(TF_GCP_02)
exception[k] {
    input.resource.google_storage_bucket_iam_member
    member := input.resource.google_storage_bucket_iam_member[k]
    checks := split(member["//"], ",")
    contains(checks[_], check02)
}

deny_public_iam_member[msg] {
    input.resource.google_storage_bucket_iam_member
    member := input.resource.google_storage_bucket_iam_member[k]

    not exception[k]
    
    msg = sprintf("%s: public users not allowed for bucket: %s", [check02, member.bucket])
}
