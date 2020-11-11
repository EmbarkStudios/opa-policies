package docker

import data.docker

exception[rules] {
  # Logic

  rules = ["no_user"]
}


# DENY(DOCKER_01): if USER is not specified in the Dockerfile it will use root implicitly
deny_no_user[msg] {
    not is_user
    msg = "DOCKER_01: Please specify a USER, root is not permitted"
}
