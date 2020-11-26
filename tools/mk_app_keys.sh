#!/bin/bash

if [ $# != 1 ]; then
    echo "Usage: mk_app_keys.sh <app_name>"
    exit 1
fi

username=${1//./-}

echo "Will create a new user: $username"

adduser --disabled-login --home /app/$1 --shell /usr/sbin/nologin --no-create-home --quiet $username

if [ $? != 0 ]; then
    echo "Failed to create a user $user for the app: $1; please run this script by root"
    exit 1
fi

openssl genpkey -out private-$1.pem -algorithm rsa
openssl rsa -in private-$1.pem -outform PEM -pubout -out public-$1.pem

cat private-$1.pem | sed -n '3,3p' > hmac-$1.key

mkdir -p /app/$1/private/
chown $username.$username /app/$1 -R
chmod go-rwx /app/$1/private

chown $username.$username private-$1.pem
chmod 400 private-$1.pem
mv private-$1.pem /app/$1/private/

chown root.root public-$1.pem
chmod 644 public-$1.pem
mv public-$1.pem /etc/public-keys/

chown $username.$username hmac-$1.key
chmod 400 hmac-$1.key
mv hmac-$1.key /app/$1/private/

exit 0
