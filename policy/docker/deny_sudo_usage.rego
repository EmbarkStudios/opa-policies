package docker

import rego.v1

import data.docker
import data.lib as l

check04 := "DOCKER_04"

exception contains rules if {
	make_exception(check04)
	rules = ["sudo_usage"]
}

# DENY(DOCKER_04): Do not allow usage of sudo
deny_sudo_usage contains msg if {
	docker.runs[run]
	contains(lower(run), "sudo")
	msg = sprintf("%s: Avoid using 'sudo' command (%s). More info: %s", [check04, run, l.get_url(check04)])
}
