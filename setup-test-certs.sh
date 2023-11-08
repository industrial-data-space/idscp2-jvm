#!/bin/bash

cd idscp2-core/src/test/resources/ssl || exit

# Delete old certificates
rm ./*.p12

# Generate a self-signed root certificate
openssl req -x509 -newkey rsa:2048 -keyout root.key -out root.crt -days 3650 -passout pass:password -subj "/CN=root"

# Create a truststore containing the root certificate
keytool -importcert -file root.crt -keystore truststore.p12 -storetype PKCS12 -storepass password -alias ca -noprompt

# Generate a private key and certificate for localhost
openssl req -newkey rsa:2048 -nodes -keyout localhost.key -out localhost.csr -subj "/CN=localhost"
openssl x509 -req -in localhost.csr -CA root.crt -CAkey root.key -CAcreateserial -passin pass:password -out localhost.crt -days 3650 -extfile <(echo -e "subjectAltName=DNS:localhost")

# Create a p12 file containing the localhost certificate and private key
openssl pkcs12 -export -in localhost.crt -inkey localhost.key -out localhost.p12 -password pass:password

# Clean up temporary files
rm root.crt root.key localhost.csr localhost.crt localhost.key root.srl
