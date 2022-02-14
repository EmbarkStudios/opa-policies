package terraform_aws

import data.lib as l
import data.terraform

check02 := "TF_AWS_02"

aws_public_access_enabled(eks_cluster) {
	not eks_cluster.public_access_cidrs
    } else { 
	l.contains_element(["0.0.0.0/0"], eks_cluster.public_access_cidrs[i])
}

# DENY(TF_AWS_02) - aws_eks_cluster
deny_aws_public_access_enabled[msg] {
	input.resource.aws_eks_cluster
	eks_cluster := input.resource.aws_eks_cluster[_]

	not make_exception(check01, eks_cluster)

	aws_public_access_enabled(eks_cluster)

	msg = sprintf("%s: Public access enabled in cluster %s (enabled by default if not specified). More info: %s", [check02, eks_cluster.name, l.get_url(check02)])
}
