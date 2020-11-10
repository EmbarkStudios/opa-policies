package terraform_gcp

import data.terraform

check03 := "TF_GCP_03"

# DENY(TF_GCP_03)
exception[k] {
    terraform.resource[r]
    binding := r.google_storage_bucket_iam_binding[k]
    binding["//"] == check03
}

deny_public_iam_binding[msg] {
    terraform.resource[r]
    binding := r.google_storage_bucket_iam_binding[k]

    not exception[k]

    msg = sprintf("%s: public users not allowed for bucket: %s", [check03, binding.bucket])
}
