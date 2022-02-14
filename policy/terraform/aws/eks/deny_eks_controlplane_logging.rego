package terraform_aws

import data.lib as l
import data.terraform

check01 := "TF_AWS_01"

aws_controlplane_logging_disabled(eks_cluster) {
	not eks_cluster.enabled_cluster_log_types
} else { 
	eks_cluster.enabled_cluster_log_types != ["api", "audit"]
}

# DENY(TF_AWS_01) - aws_eks_cluster
deny_aws_controlplane_logging_disabled[msg] {
	input.resource.aws_eks_cluster
	eks_cluster := input.resource.aws_eks_cluster[_]

	not make_exception(check01, eks_cluster)

	aws_controlplane_logging_disabled(eks_cluster)

	msg = sprintf("%s: enabled_cluster_log_types not set correctly in cluster %s. More info: %s", [check01, eks_cluster.name, l.get_url(check01)])
}
