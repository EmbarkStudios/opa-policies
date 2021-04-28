package docker

import data.lib as l

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
	run = concat(" ", input[i].Value)
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

make_exception(check) {
	labels[_][i] == "embark.dev/opa-docker"
	exclusions := split(labels[_][_], ",")
	l.contains_element(exclusions, check)
}
