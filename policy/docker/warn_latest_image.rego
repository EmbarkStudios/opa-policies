package docker

import data.docker

check03 := "DOCKER_03"

exception[rules] {
    make_exception(check03)
    rules = ["root_alias"]
}

image_tag_list = [
    "latest",
    "LATEST",
]

# WARN(DOCKER_03): Using latest can result in unpredictive behavior
warn_latest_tag[msg] {
    docker.froms[from]
    val := split(from, ":")
    contains(val[1], image_tag_list[_])
    msg = sprintf("%s: Do not use latest tag with image (%s)", [check03, from])
}
