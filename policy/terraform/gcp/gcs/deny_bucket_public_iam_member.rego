package terraform_gcp

check02 := "TF_GCP_02"

# DENY(TF_GCP_02)
exception[k] {
    input.resource.google_storage_bucket_iam_member
    member := input.resource.google_storage_bucket_iam_member[k]
    checks := split(member["//"], ",")
    contains_element(checks, check02)
}

deny_public_iam_member[msg] {
    input.resource.google_storage_bucket_iam_member
    member := input.resource.google_storage_bucket_iam_member[k]

    not exception[k]
    contains_element(blacklisted_users, member.member)
    
    msg = sprintf("%s: public users not allowed for bucket: %s", [check02, member.bucket])
}
