# Server setup

Based on [MQTTS : How to use MQTT with TLS?](https://openest.io/en/2020/01/03/mqtts-how-to-use-mqtt-with-tls/).

# Certificate Authority (CA)
Generate key and certificate for CA.

```
mkdir -p certs/ca
openssl req -new -x509 -days 365 -extensions v3_ca -keyout certs/ca/ca.key -out certs/ca/ca.crt
```

# Certificate for the MQTTS broker

Generate broker key.

```
mkdir -p certs/broker
openssl genrsa -out certs/broker/broker.key 2048
```

Create CSR using key.

```
openssl req -out certs/broker/broker.csr -key certs/broker/broker.key -new
```

Pass CSR to CA. This will use X.509 version 3, as the default, version 1, is not supported by rustls.

```
cat << EOF > certs/broker/v3.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
EOF


openssl x509 -req -in certs/broker/broker.csr -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial -out certs/broker/broker.crt -days 200 -extfile certs/broker/v3.ext
```

# MQTT client certificate

Generate client certificate for client authentication.  This will use X.509 version 3, as the default, version 1, is not supported by rustls.

```
mkdir -p certs/client
openssl genrsa -out certs/client/client.key 2048
openssl req -out certs/client/client.csr -key certs/client/client.key -new

cat << EOF > certs/client/v3.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
EOF

openssl x509 -req -in certs/client/client.csr -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial -out certs/client/client.crt -days 200 -extfile certs/client/v3.ext
```

# Mosquitto Passwd

Generate mosquitto passwd.

```
mkdir -p pwd
docker run -it --entrypoint sh -v $(pwd)/mosquitto-config:/mosquitto-config eclipse-mosquitto
mosquitto_passwd -c -b /mosquitto-config/passwd johndoe pass
exit
```

# Run
```
docker-compose up -d
```