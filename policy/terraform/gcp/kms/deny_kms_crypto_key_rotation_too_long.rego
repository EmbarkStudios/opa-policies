package terraform_gcp

import data.lib as l
import data.terraform

check35 = "TF_GCP_35"

invalid_rotation_period(key) {
	not key.rotation_period
} else {
	seconds := trim_right(key.rotation_period, "s")

	# 90 days = 7776000 seconds
	to_number(seconds) > 7776000
}

deny_kms_crypto_key_rotation_too_long[msg] {
	input.resource.google_kms_crypto_key

	key := input.resource.google_kms_crypto_key[_]

	not make_exception(check35, key)

	invalid_rotation_period(key)

	msg = sprintf("%s: KMS Crypto Key %s has a rotation period longer than 90 days. More info: %s", [check35, key.name, l.get_url(check35)])
}
