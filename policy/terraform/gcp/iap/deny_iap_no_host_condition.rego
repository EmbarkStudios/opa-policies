package terraform_gcp

import data.lib as l
import data.terraform

check43 := "TF_GCP_43"

doesnt_have_host_condition(member) {
	not member.condition.expression
} else {
	not contains(member.condition.expression, "request.host")
}

# DENY(TF_GCP_43)
deny_iap_no_host_condition[msg] {
	input.resource.google_iap_web_iam_member
	member := input.resource.google_iap_web_iam_member[k]
	not make_exception(check43, member)
	doesnt_have_host_condition(member)

	msg = sprintf("%s: %s does not contain a host condition. More info: %s", [check43, member.member, l.get_url(check43)])
}
