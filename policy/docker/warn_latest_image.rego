package docker

import rego.v1

import data.docker
import data.lib as l

check03 := "DOCKER_03"

exception contains rules if {
	make_exception(check03)
	rules = ["root_alias"]
}

image_tag_list := [
	"latest",
	"LATEST",
]

# WARN(DOCKER_03): Using latest can result in unpredictive behavior
warn_latest_tag contains msg if {
	docker.froms[from]
	val := split(from, ":")
	contains(val[1], image_tag_list[_])
	msg = sprintf("%s: Do not use latest tag with image (%s). More info: %s", [check03, from, l.get_url(check03)])
}
