package kubernetes

import data.kubernetes

# DENY(K8S_12): Specifying HostPorts
# Descriptions: Don’t specify a hostPort for a Pod unless it is absolutely necessary.
#        When you bind a Pod to a hostPort, it limits the number of places the
#        Pod can be scheduled, because each <hostIP, hostPort, protocol> combination
#        must be unique.
# Links:
#   
warn_specify_host_port[msg] {
    id := "K8S_12"
    kubernetes.containers[container]
    container.ports[port].hostPort
    
    msg = sprintf("%s: %s in the %s %s is specifying hostPort", [id, container.name, kubernetes.kind, kubernetes.name])
}