package terraform_aws

import data.lib as l
import data.terraform

check05 := "TF_AWS_05"

aws_eks_node_group_instance_types(node_group) {
	not node_group.instance_types
}

# DENY(TF_AWS_05) - aws_eks_node_group
deny_aws_eks_node_group_instance_types[msg] {
	input.resource.aws_eks_node_group
	node_group := input.resource.aws_eks_node_group[i]

	not make_exception(check05, node_group)

	aws_eks_node_group_instance_types(node_group)

	msg = sprintf("%s: Instance type not set on node group %s. More info: %s", [check05, node_group.node_group_name, l.get_url(check05)])
}
