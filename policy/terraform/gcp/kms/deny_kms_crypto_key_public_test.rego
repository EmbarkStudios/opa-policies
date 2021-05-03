package terraform_gcp

import data.testing as t

test_deny_public_kms_crypto_key_iam_member {
   input := {
       "resource": {
           "google_kms_crypto_key_iam_member": {
               "allUsers": {
                   "crypto_key_id": "some-id",
                   "role": "roles/cloudkms.cryptoKeyEncrypter",
                   "member": "allUsers",
               },
               "allAuthenticated": {
                   "crypto_key_id": "some-id",
                   "role": "roles/cloudkms.cryptoKeyEncrypter",
                   "member": "allAuthenticatedUsers",
               },
           }
       }
   }

   t.error_count(deny_kms_crypto_key_iam_member_public, 2) with input as input
}

test_allow_valid_kms_crypto_key_iam_member {
   input := {
       "resource": {
           "google_kms_crypto_key_iam_member": {
               "allUsers": {
                   "//": "TF_GCP_30",
                   "crypto_key_id": "some-id",
                   "role": "roles/cloudkms.cryptoKeyEncrypter",
                   "member": "allUsers",
               },
               "validUser": {
                   "crypto_key_id": "some-id",
                   "role": "roles/cloudkms.cryptoKeyEncrypter",
                   "member": "user:jane@example.com",
               },
           }
       }
   }

   t.no_errors(deny_kms_crypto_key_iam_member_public) with input as input
}

test_deny_public_kms_crypto_key_iam_binding {
   input := {
       "resource": {
           "google_kms_crypto_key_iam_binding": {
               "allUsers": {
                   "crypto_key_id": "some-id",
                   "role": "roles/cloudkms.cryptoKeyEncrypter",
                   "members": ["allUsers"],
               },
               "allAuthenticated": {
                   "crypto_key_id": "some-id",
                   "role": "roles/cloudkms.cryptoKeyEncrypter",
                   "members": ["allAuthenticatedUsers"],
               },
           }
       }
   }

   t.error_count(deny_kms_crypto_key_iam_binding_public, 2) with input as input
}

test_allow_valid_kms_crypto_key_iam_binding {
   input := {
       "resource": {
           "google_kms_crypto_key_iam_binding": {
               "allUsers": {
                   "//": "TF_GCP_31",
                   "crypto_key_id": "some-id",
                   "role": "roles/cloudkms.cryptoKeyEncrypter",
                   "members": ["allUsers"],
               },
               "validUsers": {
                   "crypto_key_id": "some-id",
                   "role": "roles/cloudkms.cryptoKeyEncrypter",
                   "members": ["user:jane@example.com"],
               },
           }
       }
   }

   t.no_errors(deny_kms_crypto_key_iam_binding_public) with input as input
}
