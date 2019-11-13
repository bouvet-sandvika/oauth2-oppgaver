#!/bin/bash

export CERT_ALIAS='oauth2-client'
export KEYSTORE="${CERT_ALIAS}.jks"
export STOREPASS='Super Secret JWT Keypass'
export DNAME="CN=${CERT_ALIAS}, OU=Sandvika, O=Bouvet, L=Sandvika, ST=Bærum, C=no"
export EXT="SAN=dns:localhost,dns:${CERT_ALIAS}"
export PEM_FILE="${CERT_ALIAS}".pem

export CERT_PUBLIC_ALIAS="${CERT_ALIAS}-public"
export KEYSTORE_PUBLIC="${CERT_PUBLIC_ALIAS}.jks"
export STOREPASS_PUBLIC='Super Secret JWT Keypass'
export CERT_PUBLIC_FILE="${CERT_PUBLIC_ALIAS}".cer
export KEY_PUBLIC_FILE="${CERT_PUBLIC_ALIAS}".pubkey

if [[ -f "${KEYSTORE}" ]]; then
  echo "Confirm deletion of previously generated files:"
  rm -i "${KEYSTORE}" "${PEM_FILE}" "${KEYSTORE_PUBLIC}" "${CERT_PUBLIC_FILE}" "${KEY_PUBLIC_FILE}"
fi
mkdir -p "$(dirname ${KEYSTORE})" "$(dirname ${PEM_FILE})" "$(dirname ${KEYSTORE_PUBLIC})" "$(dirname ${CERT_PUBLIC_FILE})" "$(dirname ${KEY_PUBLIC_FILE})"

echo "Creating keystore with keypair"
keytool -keystore "${KEYSTORE}" -storepass "${STOREPASS}" -storetype PKCS12 \
  -genkeypair -alias "${CERT_ALIAS}" -keypass "${STOREPASS}" \
  -keyalg RSA -keysize 2048 -validity 360 \
  -dname "${DNAME}" -ext "${EXT}"

echo "Exporting keystore as PEM"
openssl pkcs12 -in "${KEYSTORE}" -passin "pass:${STOREPASS}" -out "${PEM_FILE}" -passout "pass:${STOREPASS}"

echo "Exporting public certificate"
keytool -keystore "${KEYSTORE}" -storepass "${STOREPASS}" \
  -alias "${CERT_ALIAS}" -export -file "${CERT_PUBLIC_FILE}"

echo "Exporting public key"
keytool -keystore "${KEYSTORE}" -storepass "${STOREPASS}" \
  -list -rfc | openssl x509 -inform pem -pubkey -noout > "${KEY_PUBLIC_FILE}"

echo "Creating public keystore with public certificate"
keytool -keystore "${KEYSTORE_PUBLIC}" -storepass "${STOREPASS_PUBLIC}" -storetype PKCS12 \
  -importcert -alias "${CERT_PUBLIC_ALIAS}" -keypass "${STOREPASS_PUBLIC}" -file "${CERT_PUBLIC_FILE}" -noprompt

echo "Done"
