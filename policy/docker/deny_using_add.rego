package docker

import data.docker
import data.lib as l

check05 := "DOCKER_05"

exception[rules] {
	make_exception(check05)
	rules = ["using_add"]
}

# DENY(DOCKER_05): Use ADD instead of COPY - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy
deny_using_add[msg] {
	docker.adds[add]
	msg = sprintf("%s: Use COPY instead of ADD. More info: %s", [check05, l.get_url(check05)])
}
