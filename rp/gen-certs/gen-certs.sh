#!/bin/bash
# Author: Alexandre Giron and Frederico Schardong
# Script for generating Classical and PQC certificates from a list of algorithms in Docker

#Conf Files
prefix="rp"
op_prefix="op"
serverIP="${RP_IP:-rp}"
serverIPOP="${OP_IP:-op}"
subjectAltNameType="${SUBJECT_ALT_NAME_TYPE:-DNS}"
WORKING_DIR="${prefix}_certs"
OP_CERTS="op_certs"
OQS_OPENSSL_DIR="/usr/local/bin/"
export OPENSSL_CONF=/etc/ssl/openssl.cnf

rootconf="cert-confs/openssl_root_conf.cnf"
intermediateconf="cert-confs/openssl_intermediate.cnf"
intermediateExt="cert-confs/IntCA-extensions-x509.cnf"
serverconf="cert-confs/openssl_server.cnf"
endcertExt="cert-confs/EndCert-extensions-x509.cnf"
endcertExtOP="cert-confs/EndCert-extensions-x509.cnf"
clientconf="cert-confs/openssl_client_auth.cnf"

rootCADir="$WORKING_DIR/RootCA"
intermediaryCAsDir="$WORKING_DIR/IntermediaryCAs"
serverCerts="$WORKING_DIR/ServerCerts"
opServerCerts="$OP_CERTS/ServerCerts"
opServerCertsRPOIDC="$OP_CERTS/ServerCertsRPOIDC"
# opServerCertsOIDC="$OP_CERTS/ServerCertsOIDC"
# opServerCertsOIDCRoot="$OP_CERTS/ServerCertsOIDCRoot"
# opServerCertsOIDCIntermediate="$OP_CERTS/ServerCertsOIDCIntermediate"
JWTKeys="$WORKING_DIR/JWTKeys/"

#Certificate Algos
#should this come from a separate file?
declare -a arrayalgos=("rsa" "ecdsa" "dilithium2" "dilithium3" "dilithium5" "falcon512" "falcon1024" "sphincsshake256128fsimple" "sphincsshake256192fsimple" "sphincsshake256256fsimple") 

declare -A signatureSizes

signatureSizes["rsa"]=256
signatureSizes["ecdsa"]=70
signatureSizes["dilithium2"]=2420
signatureSizes["dilithium3"]=3293
signatureSizes["dilithium5"]=4595
signatureSizes["falcon512"]=656
signatureSizes["falcon1024"]=1275
signatureSizes["sphincsshake256128fsimple"]=17088
signatureSizes["sphincsshake256192fsimple"]=35664
signatureSizes["sphincsshake256256fsimple"]=49856

echo "-------------------------------------------------------------------------------------------------------------"
echo "Generating Self-signed (root) CA certs:"
mkdir -p $rootCADir
# mkdir -p $opServerCertsOIDCRoot

for algo in "${arrayalgos[@]}"; do
    echo "Generating for: $algo"

    if [ "$algo" = "ecdsa" ]; then
        $OQS_OPENSSL_DIR/openssl ecparam -genkey -name prime256v1 -noout -out "$rootCADir/${prefix}_$algo.key"
    else
        if [ "$algo" = "rsa" ]; then
            $OQS_OPENSSL_DIR/openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out "$rootCADir/${prefix}_$algo.key"
        else
            $OQS_OPENSSL_DIR/openssl genpkey -algorithm $algo -out "$rootCADir/${prefix}_$algo.key"
        fi
    fi
    
    #Gen self-signed certificate
    $OQS_OPENSSL_DIR/openssl req -x509 -new -key "$rootCADir/${prefix}_$algo.key" -out "$rootCADir/${prefix}_$algo.crt" -nodes -subj "/CN=LABSEC oqstest CA" -extensions v3_ca -config $rootconf -days 1095
done

echo "-------------------------------------------------------------------------------------------------------------"
echo "Generating Intermediate CAs certs:"
mkdir -p $intermediaryCAsDir
# mkdir -p $opServerCertsOIDCIntermediate

for algo in "${arrayalgos[@]}"; do
    echo "Generating for: $algo"
    
    if [ "$algo" = "ecdsa" ]; then
        $OQS_OPENSSL_DIR/openssl ecparam -genkey -name prime256v1 -noout -out "$intermediaryCAsDir/${prefix}_$algo.key"
    else
        if [ "$algo" = "rsa" ]; then
            $OQS_OPENSSL_DIR/openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out "$intermediaryCAsDir/${prefix}_$algo.key"
        else
            $OQS_OPENSSL_DIR/openssl genpkey -algorithm $algo -out "$intermediaryCAsDir/${prefix}_$algo.key"
        fi
    fi
        
    #Gen request (Using same configuration as RootCA)
    $OQS_OPENSSL_DIR/openssl req -new -key "$intermediaryCAsDir/${prefix}_$algo.key" -out "$intermediaryCAsDir/${prefix}_$algo.csr" -nodes -subj "/CN=LABSEC oqstest IntCA" -config $intermediateconf -addext basicConstraints=critical,CA:true,pathlen:0 -addext keyUsage=critical,digitalSignature,cRLSign,keyCertSign

    #Sign it by the corresponding root CA, generating the certificate
    $OQS_OPENSSL_DIR/openssl x509 -req -in "$intermediaryCAsDir/${prefix}_$algo.csr" -out "$intermediaryCAsDir/${prefix}_$algo.crt" -CA "$rootCADir/${prefix}_$algo.crt" -CAkey "$rootCADir/${prefix}_$algo.key" -CAcreateserial -days 1095 -extensions v3_ca -extfile "$intermediateExt"

    #Create bundle
    cat "$intermediaryCAsDir/${prefix}_$algo.crt" "$rootCADir/${prefix}_$algo.crt" > "$intermediaryCAsDir/bundlecerts_chain_${prefix}_$algo.crt"
done

echo "-------------------------------------------------------------------------------------------------------------"
echo "Generating Server-certs (2-level chain): for /CN=$serverIP subjectAltName=$subjectAltNameType:$serverIP"
mkdir -p $serverCerts
# mkdir -p $opServerCertsOIDC
mkdir -p $opServerCertsRPOIDC

for algo in "${arrayalgos[@]}"; do
    echo "Generating for: $algo"

    if [ "$algo" = "ecdsa" ]; then
        $OQS_OPENSSL_DIR/openssl ecparam -genkey -name prime256v1 -noout -out "$serverCerts/${prefix}_${algo}_$serverIP.key"
    else
        if [ "$algo" = "rsa" ]; then
            $OQS_OPENSSL_DIR/openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out "$serverCerts/${prefix}_${algo}_$serverIP.key"
        else
            $OQS_OPENSSL_DIR/openssl genpkey -algorithm $algo -out "$serverCerts/${prefix}_${algo}_$serverIP.key"
        fi
    fi
    
    SCT="1.3.6.1.4.1.11129.2.4.2=ASN1:OCTETSTRING:$($OQS_OPENSSL_DIR/openssl rand -hex ${signatureSizes[$algo]})"
    altName="subjectAltName = $subjectAltNameType:$serverIP"

    #add our new SCT
    echo $altName >> $endcertExt
    echo $SCT >> $endcertExt
    
    #Gen csr request (for localhost test)
    $OQS_OPENSSL_DIR/openssl req -new -key "$serverCerts/${prefix}_${algo}_$serverIP.key" -out "$serverCerts/${prefix}_${algo}_$serverIP.csr" -nodes -subj "/CN=$serverIP" -addext basicConstraints=CA:FALSE -addext extendedKeyUsage=serverAuth -addext keyUsage=critical,digitalSignature,keyEncipherment -addext "$altName" -addext $SCT

    #Generating certificates from csr
    $OQS_OPENSSL_DIR/openssl x509 -req -in "$serverCerts/${prefix}_${algo}_$serverIP.csr" -out "$serverCerts/${prefix}_${algo}_$serverIP.crt" -CA "$intermediaryCAsDir/${prefix}_$algo.crt" -CAkey "$intermediaryCAsDir/${prefix}_$algo.key" -CAcreateserial -days 1095 -extensions server_cert -extfile "$endcertExt"
    
    $OQS_OPENSSL_DIR/openssl x509 -in "$serverCerts/${prefix}_${algo}_$serverIP.crt" -text
    
    #Create bundle
    cat "$serverCerts/${prefix}_${algo}_$serverIP.crt" "$intermediaryCAsDir/bundlecerts_chain_${prefix}_$algo.crt" > "$serverCerts/bundlecerts_chain_${prefix}_${algo}_$serverIP.crt"
       
    # -------------------------------------*********** op **********---------------------------------------------

    SCTOP="1.3.6.1.4.1.11129.2.4.2=ASN1:OCTETSTRING:$($OQS_OPENSSL_DIR/openssl rand -hex ${signatureSizes[$algo]})"
    altNameOP="subjectAltName = $subjectAltNameType:$serverIPOP"

    #add our new SCT
    echo $altNameOP >> $endcertExtOP
    echo $SCTOP >> $endcertExtOP

    # # Generate oidc key and csr

    # echo "Generating certificated from op csr using rp "

    # #Generating certificated from op csr using rp 
    # $OQS_OPENSSL_DIR/openssl x509 -req -in "$opServerCerts/${op_prefix}_${algo}_$serverIPOP.csr" -out "$opServerCertsOIDC/${op_prefix}_${algo}_$serverIPOP.crt" -CA "$serverCerts/${prefix}_${algo}_$serverIP.crt" -CAkey "$serverCerts/${prefix}_${algo}_$serverIP.key" -CAcreateserial -days 1095 -extensions server_cert -extfile "$endcertExtOP"
    
    # $OQS_OPENSSL_DIR/openssl x509 -in "$opServerCertsOIDC/${op_prefix}_${algo}_$serverIPOP.crt" -text

    # #Create bundle for op csr using rp
    # cat "$opServerCertsOIDC/${op_prefix}_${algo}_$serverIPOP.crt" "$serverCerts/bundlecerts_chain_${prefix}_${algo}_$serverIP.crt" > "$opServerCertsOIDC/bundlecerts_chain_${op_prefix}_${algo}_$serverIPOP.crt"

    # # Generate oidc key and csr

    # echo "Generating certificate from op csr using rp intermediate "

    # #Generating certificated from op csr using rp 
    # $OQS_OPENSSL_DIR/openssl x509 -req -in "$opServerCerts/${op_prefix}_${algo}_$serverIPOP.csr" -out "$opServerCertsOIDCIntermediate/${op_prefix}_${algo}_$serverIPOP.crt" -CA "$intermediaryCAsDir/${prefix}_$algo.crt" -CAkey "$intermediaryCAsDir/${prefix}_$algo.key" -CAcreateserial -days 1095 -extensions server_cert -extfile "$endcertExtOP"
    
    # $OQS_OPENSSL_DIR/openssl x509 -in "$opServerCertsOIDCIntermediate/${op_prefix}_${algo}_$serverIPOP.crt" -text

    # #Create bundle for op csr using rp
    # cat "$opServerCertsOIDCIntermediate/${op_prefix}_${algo}_$serverIPOP.crt" "$intermediaryCAsDir/bundlecerts_chain_${prefix}_$algo.crt" > "$opServerCertsOIDCIntermediate/bundlecerts_chain_${op_prefix}_${algo}_$serverIPOP.crt"

    # # Generate oidc key and csr
    # echo "Generating certificate from op csr using rp Root "

    # #Generating certificated from op csr using rp
    # $OQS_OPENSSL_DIR/openssl x509 -req -in "$opServerCerts/${op_prefix}_${algo}_$serverIPOP.csr" -out "$opServerCertsOIDCRoot/${op_prefix}_${algo}_$serverIPOP.crt" -CA "$rootCADir/${prefix}_$algo.crt" -CAkey "$rootCADir/${prefix}_$algo.key" -CAcreateserial -days 1095 -extensions server_cert -extfile "$endcertExtOP"
    
    # $OQS_OPENSSL_DIR/openssl x509 -in "$opServerCertsOIDCRoot/${op_prefix}_${algo}_$serverIPOP.crt" -text

    # #Create bundle for op csr using rp
    # cat "$opServerCertsOIDCRoot/${op_prefix}_${algo}_$serverIPOP.crt" "$rootCADir/${prefix}_$algo.crt" > "$opServerCertsOIDCRoot/bundlecerts_chain_${op_prefix}_${algo}_$serverIPOP.crt"


    # ********************* signing op using with generated rp self signed ******************************


    #Gen self-signed certificate
    $OQS_OPENSSL_DIR/openssl req -x509 -new -key "$serverCerts/${prefix}_${algo}_$serverIP.key" -out "$serverCerts/root_${prefix}_$algo.crt" -nodes -subj "/CN=LABSEC oqstest CA" -extensions v3_ca -config $rootconf -days 1095

    #Generating certificated from op csr using rp
    $OQS_OPENSSL_DIR/openssl x509 -req -in "$opServerCerts/${op_prefix}_${algo}_$serverIPOP.csr" -out "$opServerCertsRPOIDC/${op_prefix}_${algo}_$serverIPOP.crt" -CA "$serverCerts/root_${prefix}_$algo.crt" -CAkey  "$serverCerts/${prefix}_${algo}_$serverIP.key"  -CAcreateserial -days 1095 -extensions server_cert -extfile "$endcertExtOP"
    
    $OQS_OPENSSL_DIR/openssl x509 -in "$opServerCertsRPOIDC/${op_prefix}_${algo}_$serverIPOP.crt" -text

    #Create bundle for op csr using rp
    cat "$opServerCertsRPOIDC/${op_prefix}_${algo}_$serverIPOP.crt" "$serverCerts/root_${prefix}_$algo.crt" > "$opServerCertsRPOIDC/bundlecerts_chain_${op_prefix}_${algo}_$serverIPOP.crt"
done
