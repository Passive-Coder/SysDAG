#!/bin/sh
cat /guest/decoy/secret.txt >/dev/null
/bin/sh -c "echo shell-spawn"
