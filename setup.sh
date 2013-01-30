#!/bin/bash

set -x

# This script expects an active virtualenv

if [ -z "$VIRTUAL_ENV" ]; then
    echo "abort: no virtual environment active"
    exit 1
fi

# This scripts expects to find zap.sh on the path

if [ ! `which zap.sh` ]; then
	echo "abort: no zap.sh found on your path"
	exit 1
fi

case $1 in
    develop)
        python setup.py develop
        ;;
esac
