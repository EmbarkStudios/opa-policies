package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_06): Don't allow usage of default service account
# Description:
# Links:
#
checks06 := "K8S_06"

exception contains rules if {
	make_exception(checks06)
	rules = ["default_service_account"]
}

invalid_service_account(pod) if {
	not pod.spec.serviceAccountName
} else if {
	sa := pod.spec.serviceAccountName
	sa == "default"
}

deny_default_service_account contains msg if {
	kubernetes.pods[pod]
	true in [invalid_service_account(pod)]
	msg = sprintf("%s: the %s %s is using a default service account. More info: %s", [checks06, kubernetes.kind, kubernetes.name, l.get_url(checks06)])
}
