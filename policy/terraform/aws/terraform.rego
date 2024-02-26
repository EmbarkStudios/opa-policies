package terraform_aws

import data.lib as l

make_exception(check, obj) {
	checks := split(obj["//"], ",")
	l.contains_element(checks, check)
}
