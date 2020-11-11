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

labels[label] {
    input[i].Cmd == "label"
    label = input[i].Value[j]
}
