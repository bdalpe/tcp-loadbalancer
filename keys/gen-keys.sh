#!/bin/sh
openssl genrsa -out key.pem 2048
openssl req -x509 -new -nodes -key key.pem -sha256 -days 3165 -out cert.pem -subj '/CN=logstream'