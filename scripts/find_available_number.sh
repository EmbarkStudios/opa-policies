#!/bin/sh
set -ex
echo $1

rg "$1" | sed -r "s/.*($1_[0-9]+).*/\1/g" | sort -u
