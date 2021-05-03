package kubernetes

import data.kubernetes
import data.lib as l

# DENY(K8S_03): Using latest leads to unpredictable behavior
# Description:
# Links:
#
check03 := "K8S_03"

exception[rules] {
	make_exception(check03)
	rules = ["usage_of_latest_tag"]
}

deny_usage_of_latest_tag[msg] {
	kubernetes.containers[container]
	[image_name, "latest"] = kubernetes.split_image(container.image)
	msg = sprintf("%s: %s in the %s %s has an image, %s, using the latest tag. More info: %s", [check03, container.name, kubernetes.kind, image_name, kubernetes.name, l.get_url(check03)])
}
