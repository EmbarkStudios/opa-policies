package docker

import data.docker

check04 := "DOCKER_04"

exception[rules] {
    make_exception(check04)
    rules = ["sudo_usage"]
}

# DENY(DOCKER_04): Do not allow usage of sudo
deny_sudo_usage[msg] {
    docker.runs[run]
    contains(lower(run), "sudo")
    msg = sprintf("%s: Avoid using 'sudo' command (%s). More info: %s", [check04, run, get_url(check04)])
}
