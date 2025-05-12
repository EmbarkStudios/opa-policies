package testing

import rego.v1

no_errors(target) if {
	count(target) == 0
}

error_count(target, c) if {
	count(target) == c
}
