#!/bin/bash

export CERT_ALIAS='authorization-server'
export KEYSTORE="${CERT_ALIAS}.jks"
export STOREPASS='Super Secret JWT Keypass'
export DNAME="CN=${CERT_ALIAS}, OU=Sandvika, O=Bouvet, L=Sandvika, ST=Bærum, C=no"
export EXT="SAN=dns:localhost,dns:${CERT_ALIAS}"

export CERT_PUBLIC_ALIAS="${CERT_ALIAS}-public"
export KEYSTORE_PUBLIC="${CERT_PUBLIC_ALIAS}.jks"
export STOREPASS_PUBLIC='Super Secret JWT Keypass'
export CERT_PUBLIC_FILE="${CERT_PUBLIC_ALIAS}".cer
export PEM_PUBLIC_FILE="${CERT_PUBLIC_ALIAS}".pem
export KEY_PUBLIC_FILE="${CERT_PUBLIC_ALIAS}".pubkey

if [[ -f "${KEYSTORE}" ]]; then
  echo "Confirm deletion of previously generated files:"
  rm -i "${KEYSTORE}" "${KEYSTORE_PUBLIC}" "${CERT_PUBLIC_FILE}" "${PEM_PUBLIC_FILE}" "${KEY_PUBLIC_FILE}"
fi
mkdir -p "$(dirname ${KEYSTORE})" "$(dirname ${KEYSTORE_PUBLIC})" "$(dirname ${CERT_PUBLIC_FILE})" "$(dirname ${PEM_PUBLIC_FILE})" "$(dirname ${KEY_PUBLIC_FILE})"

echo "Creating keystore with keypair"
keytool -keystore "${KEYSTORE}" -storepass "${STOREPASS}" -storetype PKCS12 \
  -genkeypair -alias "${CERT_ALIAS}" -keypass "${STOREPASS}" \
  -keyalg RSA -keysize 2048 -validity 360 \
  -dname "${DNAME}" -ext "${EXT}"

echo "Exporting public certificate"
keytool -keystore "${KEYSTORE}" -storepass "${STOREPASS}" \
  -alias "${CERT_ALIAS}" -export -file "${CERT_PUBLIC_FILE}"

echo "Exporting public certificate as PEM"
openssl x509 -inform DES -in "${CERT_PUBLIC_FILE}" -out "${PEM_PUBLIC_FILE}"

echo "Exporting public key"
keytool -keystore "${KEYSTORE}" -storepass "${STOREPASS}" \
  -list -rfc | openssl x509 -inform pem -pubkey -noout > "${KEY_PUBLIC_FILE}"

echo "Creating public keystore with public certificate"
keytool -keystore "${KEYSTORE_PUBLIC}" -storepass "${STOREPASS_PUBLIC}" -storetype PKCS12 \
  -importcert -alias "${CERT_PUBLIC_ALIAS}" -keypass "${STOREPASS_PUBLIC}" -file "${CERT_PUBLIC_FILE}" -noprompt

echo "Done"
