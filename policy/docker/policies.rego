package docker

# References:
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
# https://cloudberry.engineering/article/dockerfile-security-best-practices/
# https://github.com/hadolint/hadolint#rules

any_user {
    input[i].Cmd == "user"
}

# DENY: if USER is not specified in the Dockerfile it will use root implicitly
deny[msg] {
    not any_user
    msg = "Please specify a USER, root is not permitted"
}


root_alias = [
    "root",
    "toor",
    "0"
]

# DENY: if USER is set to any of the possible root users
deny[msg] {
    input[i].Cmd == "user"
    contains(lower(input[i].Value[_]), root_alias[_])
    msg = "Please specify another USER, root is not permitted"
}

image_tag_list = [
    "latest",
    "LATEST",
]

# WARN: Using latest can result in unpredictive behavior
warn[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    contains(val[1], image_tag_list[_])
    msg = sprintf("Do not use latest tag with image: %s", [input[i].Value])
}

# DENY: Do not allow usage of sudo
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "sudo")
    msg = sprintf("Avoid using 'sudo' command: %s", [val])
}

# DENY: Use ADD instead of COPY - https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy
deny[msg] {
    input[i].Cmd == "add"
    val := concat(" ", input[i].Value)
    msg = sprintf("Use COPY instead of ADD: %s", [val])
}

# DENY: Avoid curl bashing, use a trusted source and verify hash
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    matches := regex.find_n("(curl|wget)[^|^>]*[|>]", lower(val), -1)
    count(matches) > 0
    msg = "Avoid curl/wget bashing"
}

# DENY: Port number out of range - https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
port_in_range {
    input[i].Cmd == "expose"
    all([to_number(concat(" ", input[i].Value)) > 0], to_number(concat(" ", input[i].Value)) < 65535)
}
deny[msg] {
    input[i].Cmd == "expose"

    not port_in_range
    msg = "Port number out of range (0-65535)"
}
