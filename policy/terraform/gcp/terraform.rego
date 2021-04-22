package terraform_gcp

buckets[bucket] {
	bucket = input.resource.google_storage_bucket[bucket]
}

is_true(val) = true {
    any([val == "true", val == true])
}

blacklisted_users = [
    "allUsers",
    "allAuthenticatedUsers",
]

contains_element(arr, elem) = true {
  arr[_] = elem
} else = false { true }

make_exception(check, obj) {
	checks := split(obj["//"], ",")
	contains_element(checks, check)
}

get_url(check) = url {
  url := sprintf("https://github.com/EmbarkStudios/opa-policies/wiki/%s", [check])
}
