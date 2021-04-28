package lib

has_key(obj, k) {
	_ = obj[k]
}

is_false(val) {
	any([val == "false", val == false])
}

is_true(val) {
	any([val == "true", val == true])
}

not_existing_or_true(obj, k) {
	not has_key(obj, k)
} else {
	is_true(obj[k])
}

contains_element(arr, elem) {
	arr[_] = elem
} else = false {
	true
}

get_url(check) = url {
	url := sprintf("https://github.com/EmbarkStudios/opa-policies/wiki/%s", [check])
}
