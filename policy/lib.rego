package lib

import rego.v1

has_key(obj, k) if {
	_ = obj[k]
}

is_false(val) if {
	true in [val == "false", val == false]
}

is_true(val) if {
	true in [val == "true", val == true]
}

not_existing_or_true(obj, k) if {
	not has_key(obj, k)
} else if {
	is_true(obj[k])
}

contains_element(arr, elem) if {
	arr[_] = elem
} else := false

get_url(check) := url if {
	url := sprintf("https://github.com/EmbarkStudios/opa-policies/wiki/%s", [check])
}
