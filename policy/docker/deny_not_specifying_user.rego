package docker

import data.lib as l
import data.docker

check01 := "DOCKER_01"

exception[rules] {
	make_exception(check01)
	rules = ["no_user"]
}

# DENY(DOCKER_01): if USER is not specified in the Dockerfile it will use root implicitly
deny_no_user[msg] {
	not is_user
	msg = sprintf("%s: Please specify a USER, root is not permitted. More info: %s", [check01, l.get_url(check01)])
}
