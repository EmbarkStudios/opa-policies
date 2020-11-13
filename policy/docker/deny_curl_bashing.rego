package docker

import data.docker

check06 := "DOCKER_06"

exception[rules] {
    make_exception(check06)
    rules = ["curl_bashing"]
}

# DENY(DOCKER_06): Avoid curl bashing, use a trusted source and verify hash
deny_curl_bashing[msg] {
    docker.runs[run]
    matches := regex.find_n("(curl|wget)[^|^>]*[|>]", lower(run), -1)
    count(matches) > 0
    msg = sprintf("%s: Avoid curl/wget bashing (%s)", [check06, run])
}