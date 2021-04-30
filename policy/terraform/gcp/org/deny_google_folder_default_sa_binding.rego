package terraform_gcp

import data.lib as l
import data.terraform

check38 := "TF_GCP_38"

# DENY(TF_GCP_38)
deny_default_sa_binding_on_folder_level[msg] {
	input.resource.google_folder_iam_binding
	binding := input.resource.google_folder_iam_binding[_]

	not make_exception(check38, binding)

	member := binding.members[_]
	regex.match(default_service_account_regexp, member)

	msg = sprintf("%s: default service account [%s] not allowed on folder level. More info: %s", [check38, member, l.get_url(check38)])
}
