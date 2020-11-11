package docker

# References:
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
# https://cloudberry.engineering/article/dockerfile-security-best-practices/
# https://github.com/hadolint/hadolint#rules

any_user {
    input[i].Cmd == "user"
}

# DENY(DOCKER_01): if USER is not specified in the Dockerfile it will use root implicitly
deny_no_user[msg] {
    not any_user
    msg = "DOCKER_01: Please specify a USER, root is not permitted"
}


root_alias = [
    "root",
    "toor",
    "0"
]

# DENY(DOCKER_02): if USER is set to any of the possible root users
deny_root_alias[msg] {
    input[i].Cmd == "user"
    contains(lower(input[i].Value[_]), root_alias[_])
    msg = "DOCKER_02: Please specify another USER, root is not permitted"
}

image_tag_list = [
    "latest",
    "LATEST",
]

# WARN(DOCKER_03): Using latest can result in unpredictive behavior
warn_latest_tag[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    contains(val[1], image_tag_list[_])
    msg = sprintf("DOCKER_03: Do not use latest tag with image: %s", [input[i].Value])
}

# DENY(DOCKER_04): Do not allow usage of sudo
deny_sudo_usage[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "sudo")
    msg = sprintf("DOCKER_04: Avoid using 'sudo' command: %s", [val])
}

# DENY(DOCKER_05): Use ADD instead of COPY - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy
deny_using_add[msg] {
    input[i].Cmd == "add"
    val := concat(" ", input[i].Value)
    msg = sprintf("DOCKER_05: Use COPY instead of ADD: %s", [val])
}

# DENY(DOCKER_06): Avoid curl bashing, use a trusted source and verify hash
deny_curl_bashing[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    matches := regex.find_n("(curl|wget)[^|^>]*[|>]", lower(val), -1)
    count(matches) > 0
    msg = "DOCKER_06: Avoid curl/wget bashing"
}

# DENY(DOCKER_07): Port number out of range - https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
port_in_range {
    input[i].Cmd == "expose"
    all([to_number(concat(" ", input[i].Value)) > 0], to_number(concat(" ", input[i].Value)) < 65535)
}
deny_port_out_of_range[msg] {
    input[i].Cmd == "expose"

    not port_in_range
    msg = "Port number out of range (0-65535)"
}
