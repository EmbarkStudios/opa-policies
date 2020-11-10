package kubernetes

import data.kubernetes

# DENY(K8S_03): Using latest leads to unpredictable behavior
# Description:
# Links:
#   
deny_usage_of_latest_tag[msg] {
    id := "K8S_03"
    kubernetes.containers[container]
	[image_name, "latest"] = kubernetes.split_image(container.image)
	msg = sprintf("%s: %s in the %s %s has an image, %s, using the latest tag", [id, container.name, kubernetes.kind, image_name, kubernetes.name])
}