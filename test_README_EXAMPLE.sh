#!/bin/bash
#
#   ./test_README_EXAMPLE.sh <HOSTLIST> <PORTAL_CREDS_FILE>
#
# This shell script does exactly what the Example Playbook section from README.md does.
# It can be used to test what you have uploaded to Galaxy, and ensure that the Example still
# works.
#
# <HOSTLIST> 
#
# This test requires a test host.  This must be a RHEL box (real or virtual) that
# is both registered with Red Hat Insights, and in your Ansible inventory (and reachable by ansible)
# on your development machine.  If you want to test multiple hosts, separate
# hostnames with commas.
#
# <PORTAL_CREDS_FILE> 
#
# This test requires Red Hat Insights basic auth credentials to be supplied in
# a YAML file.  I put this file outside the source repo so i don't accedently push it.
#
#    redhat_portal_username: XXXXXX
#    redhat_portal_password: YYYYYY
#
# where XXXX and YYYYY are replaced with Red Hat Portal basic auth credentials.
#

if [ "x$1" == "x" ]; then
    echo >&2 "must supply a target host to test against"
    exit 1
else
    HOSTLIST=$1
    shift
fi

DEFAULT_CREDS_FILE="redhat-portal-creds.yml"
if [ "x$1" == "x" ]; then
    if [ -e "$DEFAULT_CREDS_FILE" ]; then
        CREDS_FILE="$DEFAULT_CREDS_FILE"
    else
        echo >&2 "must supply Red Hat Portal credentials"
        exit 1
    fi
else
    CREDS_FILE=$1
    shift
fi


ansible-galaxy install --force gavin-romig-koch.insights-magpie
ansible-playbook --limit "$HOSTLIST" --extra-vars @"$CREDS_FILE" insights-magpie-example.yml
