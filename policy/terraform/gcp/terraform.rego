package terraform_gcp

buckets[bucket] {
	bucket = input.resource.google_storage_bucket[bucket]
}

is_false(val) = false {
	any([val == "false", val == false])
}

is_true(val) {
	any([val == "true", val == true])
}

has_key(obj, k) {
	_ = obj[k]
}

no_errors(target) {
	count(target) == 0
}

not_existing_or_true(obj, k) {
	not has_key(obj, k)
} else {
	is_true(obj.k)
}

blacklisted_users = [
	"allUsers",
	"allAuthenticatedUsers",
]

contains_element(arr, elem) {
	arr[_] = elem
} else = false {
	true
}

make_exception(check, obj) {
	checks := split(obj["//"], ",")
	contains_element(checks, check)
}

get_url(check) = url {
	url := sprintf("https://github.com/EmbarkStudios/opa-policies/wiki/%s", [check])
}
