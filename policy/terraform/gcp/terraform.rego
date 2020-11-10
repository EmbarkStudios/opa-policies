package terraform_gcp

buckets[bucket] {
	bucket = input.resource.google_storage_bucket[bucket]
}

# TODO(freddd): extract to util
string_true(v) = true {
	is_string(v)
    v == "true"
}

string_false(v) = false {
	is_string(v)
    v == "false"
}

is_true(obj, k) = true {
    string_true(obj[k])
} else = true {
    obj[k] == true
}

blacklisted_users = {
    "allUsers",
    "allAuthenticatedUsers",
}
