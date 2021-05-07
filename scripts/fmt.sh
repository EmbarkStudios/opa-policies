#!/bin/sh

find . -type f -name "*.rego" -a -not -name "*_test*" -exec opa fmt -w {} \;
