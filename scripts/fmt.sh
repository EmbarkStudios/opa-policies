#!/bin/sh

find . -type f -name "*.rego" | grep -v "_test" | xargs -I{} opa fmt -w {}
