package docker

import data.docker


root_alias = [
    "root",
    "toor",
    "0"
]

# DENY(DOCKER_02): if USER is set to any of the possible root users
deny_root_alias[msg] {
    docker.users[user]
    lower(users[user]) == root_alias[alias]
    msg = sprintf("DOCKER_02: Please specify another USER, root (%s) is not permitted", [user])
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
    msg = sprintf("DOCKER_03: Do not use latest tag with image (%s)", [from])
}

# DENY(DOCKER_04): Do not allow usage of sudo
deny_sudo_usage[msg] {
    docker.runs[run]
    contains(lower(run), "sudo")
    msg = sprintf("DOCKER_04: Avoid using 'sudo' command (%s)", [run])
}

# DENY(DOCKER_05): Use ADD instead of COPY - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy
deny_using_add[msg] {
    docker.adds[add]
    msg = "DOCKER_05: Use COPY instead of ADD"
}

# DENY(DOCKER_06): Avoid curl bashing, use a trusted source and verify hash
deny_curl_bashing[msg] {
    docker.runs[run]
    matches := regex.find_n("(curl|wget)[^|^>]*[|>]", lower(run), -1)
    count(matches) > 0
    msg = sprintf("DOCKER_06: Avoid curl/wget bashing (%s)", [run])
}

# DENY(DOCKER_07): Port number out of range - https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
port_in_range {
    docker.exposes[expose]
    all([to_number(expose) > 0, to_number(expose) < 65535])
}
deny_port_out_of_range[msg] {
    docker.exposes[expose]
    not port_in_range
    msg = "Port number out of range (0-65535)"
}
