package docker

import rego.v1

import data.lib as l

is_user if {
	input[i].Cmd == "user"
}

command contains cmd if {
	cmd = input[i]
}

froms contains from if {
	input[i].Cmd == "from"
	from = input[i].Value[j]
}

runs contains run if {
	input[i].Cmd == "run"
	run = concat(" ", input[i].Value)
}

users contains user if {
	input[i].Cmd == "user"
	user = input[i].Value[j]
}

adds contains add if {
	input[i].Cmd == "add"
	add = input[i].Value[j]
}

exposes contains expose if {
	input[i].Cmd == "expose"
	expose = input[i].Value[j]
}

labels contains label_values if {
	input[i].Cmd == "label"
	label_values = input[i].Value
}

make_exception(check) if {
	labels[_][i] == "embark.dev/opa-docker"
	exclusions := split(labels[_][_], ",")
	l.contains_element(exclusions, check)
}
