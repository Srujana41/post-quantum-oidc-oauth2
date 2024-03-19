# docker installation 

sudo apt-get update
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get install -y ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
sudo groupadd docker
sudo usermod -aG docker ubuntu
newgrp docker

# to start experiment 
USER_AGENT_IP=172.27.96.125 OP_IP=172.27.96.53 RP_IP=172.27.96.33 AMAZON_PEM_FILE=ssh.pem REPEAT=1 ./run_experiments.sh

# run single server on op or rp with logs
OP_IP=172.27.96.53 RP_IP=172.27.96.33 TLS_SIGN=dilithium2 JWT_SIGN=dilithium2 LOG_LEVEL=DEBUG docker-compose -f docker-compose-amazon.yml up --force-recreate op nginx >> log.txt
OP_IP=172.27.96.53 RP_IP=172.27.96.33 TLS_SIGN=dilithium2 JWT_SIGN=dilithium2 LOG_LEVEL=DEBUG docker-compose -f docker-compose-amazon.yml up --force-recreate rp >> log.txt


#user agent 
docker-compose -f docker-compose-amazon.yml up user_agent


# test ssl 

# on user agent
requests.get("https://172.27.96.243/.well-known/openid-configuration",  verify=f"/home/ubuntu/post-quantum-oidc-oauth2/rp_certs/ServerCerts/bundlecerts_chain_rp_ecdsa_172.27.96.182.crt")
requests.get("https://172.27.96.53/.well-known/openid-configuration",  verify=f"/rp_certs/ServerCertsRoot/root_rp_dilithium3.crt")
requests.get("https://172.27.96.53:8080/.well-known/openid-configuration",  verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_dilithium3.crt")


# on rp
requests.get("https://172.27.96.243/.well-known/openid-configuration",  verify=f"/op_certs/IntermediaryCAs/bundlecerts_chain_op_ecdsa.crt")




OP_IP=172.27.96.243 RP_IP=172.27.96.120 TLS_SIGN=ecdsa JWT_SIGN=ecdsa LOG_LEVEL=DEBUG REPEAT=1 TEST=$TEST docker-compose -f docker-compose-amazon.yml up --force-recreate --exit-code-from user_agent user_agent >> useragentlogs.txt