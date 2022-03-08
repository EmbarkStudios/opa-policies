package terraform_gcp

import data.lib as l
import data.terraform

check49 := "TF_GCP_49"

not_exists_or_false(redis) {
	not redis.auth_enabled
} else {
	not l.is_true(redis.auth_enabled)
}

# DENY(TF_GCP_49)
deny_memorystore_redis_no_auth[msg] {
	input.resource.google_redis_instance
	redis := input.resource.google_redis_instance[i]
	not make_exception(check49, redis)
	not_exists_or_false(redis)

	msg = sprintf("%s: AUTH should be enabled for instance [%s], More info: %s", [check49, redis.name, l.get_url(check49)])
}
