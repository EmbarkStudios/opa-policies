package kubernetes

import data.kubernetes
import data.lib as l

# DENY(K8S_11): Specifying HostPorts
# Descriptions: Don’t specify a hostPort for a Pod unless it is absolutely necessary.
#        When you bind a Pod to a hostPort, it limits the number of places the
#        Pod can be scheduled, because each <hostIP, hostPort, protocol> combination
#        must be unique.
# Links:
#
check11 := "K8S_11"

exception[rules] {
	make_exception(check11)
	rules = ["specify_host_port"]
}

warn_specify_host_port[msg] {
	kubernetes.containers[container]
	container.ports[port].hostPort

	msg = sprintf("%s: %s in the %s %s is specifying hostPort. More info: %s", [check11, container.name, kubernetes.kind, kubernetes.name, l.get_url(check11)])
}
