#!/bin/sh
echo "heartbeat" >> /guest/www/app.log
cat /guest/www/page.txt >/dev/null
