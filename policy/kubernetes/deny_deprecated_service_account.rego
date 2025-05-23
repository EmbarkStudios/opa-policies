package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_07):
# Description: Using the default service account can lead to pods being granted implicit permissions
# serviceAccount is deprecated and serviceAccountName should be used instead
checks07 := "K8S_07"

exception contains rules if {
	make_exception(checks07)
	rules = ["deprecated_service_account"]
}

deny_deprecated_service_account contains msg if {
	kubernetes.pods[pod]
	pod.spec.serviceAccount
	msg = sprintf("%s: the %s %s is using the deprecated serviceaccount, use serviceAccountName", [checks07, kubernetes.kind, kubernetes.name, l.get_url(checks07)])
}
