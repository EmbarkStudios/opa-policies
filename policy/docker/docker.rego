package docker

is_user {
	input[i].Cmd == "user"
}

command[cmd] {
	cmd = input[i]
}

froms[from] {
	input[i].Cmd == "from"
	from = input[i].Value[j]
}

runs[run] {
	input[i].Cmd == "run"
	run = input[i].Value[j]
}

users[user] {
	input[i].Cmd == "user"
	user = input[i].Value[j]
}

adds[add] {
	input[i].Cmd == "add"
	add = input[i].Value[j]
}

exposes[expose] {
	input[i].Cmd == "expose"
	expose = input[i].Value[j]
}

labels[label_values] {
	input[i].Cmd == "label"
	label_values = input[i].Value
}

contains_element(arr, elem) {
	arr[_] = elem
} else = false {
	true
}

make_exception(check) {
	labels[_][i] == "embark.dev/opa-docker"
	exclusions := split(labels[_][_], ",")
	contains_element(exclusions, check)
}

get_url(check) = url {
	url := sprintf("https://github.com/EmbarkStudios/opa-policies/wiki/%s", [check])
}
