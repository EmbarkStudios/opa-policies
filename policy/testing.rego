package testing

no_errors(target) {
	count(target) == 0
}

error_count(target, c) {
	count(target) == c
}
