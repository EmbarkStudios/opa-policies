package terraform_aws

import data.lib as l
import data.terraform

check04 := "TF_AWS_04"

aws_s3_public_acl(s3_bucket) {
	not regex.match("private.*", s3_bucket.acl)
}



# DENY(TF_AWS_04) - aws_s3_access_point
deny_aws_s3_public_acl[msg] {
	input.resource.aws_s3_access_point
	s3_bucket := input.resource.aws_s3_access_point[i]

	not make_exception(check04, s3_bucket)

	aws_s3_public_acl(s3_bucket)

	msg = sprintf("%s: ACL on bucket %s allows for public access. More info: %s", [check04, s3_bucket.name, l.get_url(check04)])
}
