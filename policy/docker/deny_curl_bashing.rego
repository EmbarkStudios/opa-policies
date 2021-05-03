package docker

import data.docker
import data.lib as l

check06 := "DOCKER_06"

exception[rules] {
	make_exception(check06)
	rules = ["curl_bashing"]
}

# DENY(DOCKER_06): Avoid curl bashing, use a trusted source and verify hash
deny_curl_bashing[msg] {
	docker.runs[run]
	regex.match("(curl|wget).*[|>].*", lower(run))
	msg = sprintf("%s: Avoid curl/wget bashing (%s). More info: %s", [check06, run, l.get_url(check06)])
}
