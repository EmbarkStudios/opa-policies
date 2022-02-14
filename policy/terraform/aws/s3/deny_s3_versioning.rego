package terraform_aws

import data.lib as l
import data.terraform

check03 := "TF_AWS_03"

aws_s3_versioning_disabled(s3_bucket) {
	not s3_bucket.versioning 
} else {
	l.is_false(s3_bucket.versioning.enabled)

}



# DENY(TF_AWS_03) - aws_s3_access_point
deny_aws_s3_versioning_disabled[msg] {
	input.resource.aws_s3_access_point
	s3_bucket := input.resource.aws_s3_access_point[i]

	not make_exception(check03, s3_bucket)

	aws_s3_versioning_disabled(s3_bucket)

	msg = sprintf("%s: Versioning not enabled on bucket %s. More info: %s", [check03, s3_bucket.name, l.get_url(check03)])
}
