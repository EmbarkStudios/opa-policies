package terraform_gcp

import rego.v1

import data.testing as t

test_deny_kms_crypto_key_rotation_too_long if {
	inp := {"resource": {"google_kms_crypto_key": {
		"key1": {
			"name": "undefined",
			"key_ring": "${google_kms_key_ring.keyring.id}",
			"purpose": "ASYMMETRIC_SIGN",
			"version_template": {"algorithm": "EC_SIGN_P384_SHA384"},
		},
		"key2": {
			"name": "too-long",
			"key_ring": "${google_kms_key_ring.keyring.id}",
			"purpose": "ASYMMETRIC_SIGN",
			"rotation_period": "7776001s",
			"version_template": {"algorithm": "EC_SIGN_P384_SHA384"},
		},
	}}}

	t.error_count(deny_kms_crypto_key_rotation_too_long, 2) with input as inp
}

test_allow_valid_kms_crypto_key_rotation if {
	inp := {"resource": {"google_kms_crypto_key": {
		"key1": {
			"name": "excepted",
			"key_ring": "${google_kms_key_ring.keyring.id}",
			"purpose": "ASYMMETRIC_SIGN",
			"//": "TF_GCP_35",
			"version_template": {"algorithm": "EC_SIGN_P384_SHA384"},
		},
		"key2": {
			"name": "valid",
			"key_ring": "${google_kms_key_ring.keyring.id}",
			"purpose": "ASYMMETRIC_SIGN",
			"rotation_period": "7776000s",
			"version_template": {"algorithm": "EC_SIGN_P384_SHA384"},
		},
	}}}

	t.no_errors(deny_kms_crypto_key_rotation_too_long) with input as inp
}
