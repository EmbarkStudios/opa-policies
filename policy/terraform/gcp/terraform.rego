package terraform_gcp

resource[r] {
	input.resource[r]
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

exists_and_true_string(obj, k) {
    obj[k]
    all([string_true(obj[k])])
}
