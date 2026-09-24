#!/bin/sh
export MDSH_XTRACE=1
mdsh -c 'mkdir -p blah.d'
mdsh -c 'touch blah.d/BLAH'
mdsh -c 'cp /etc/group blah.d/BLAH'
mdsh -c 'rm -f blah.d/BLAH'
mdsh -c 'rmdir blah.d'
