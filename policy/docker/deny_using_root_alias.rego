package docker

import data.docker
import data.lib as l

root_alias = [
	"root",
	"toor",
	"0",
]

check02 := "DOCKER_02"

exception[rules] {
	make_exception(check02)
	rules = ["root_alias"]
}

# DENY(DOCKER_02): if USER is set to any of the possible root users
deny_root_alias[msg] {
	docker.users[user]
	lower(users[user]) == root_alias[alias]
	msg = sprintf("%s: Please specify another USER, root (%s) is not permitted. More info: %s", [check02, user, l.get_url(check02)])
}
