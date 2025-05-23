package docker

import rego.v1

import data.docker
import data.lib as l

check07 := "DOCKER_07"

exception contains rules if {
	make_exception(check07)
	rules = ["port_out_of_range"]
}

# DENY(DOCKER_07): Port number out of range - https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
port_in_range if {
	docker.exposes[expose]
	to_number(expose) > 0
	to_number(expose) < 65535
}

deny_port_out_of_range contains msg if {
	docker.exposes[expose]
	not port_in_range
	msg = sprintf("%s: Port number out of range (0-65535). More info: %s", [check07, l.get_url(check07)])
}
