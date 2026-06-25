#!/bin/sh

KEY_PASS=${KEY_PASS:-defaultpassword}

keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -keystore src/main/resources/keystore.jks \
        -dname "CN=, OU=, O=, L=, ST=, C=" -storepass "$KEY_PASS" -validity 3650

keytool -genkeypair -alias jwtsign -keyalg RSA -keysize 2048 -keystore src/main/resources/jwtkeystore.jks \
        -dname "CN=, OU=, O=, L=, ST=, C=" -storepass "$KEY_PASS" -validity 3650


./mvnw spring-boot:run
