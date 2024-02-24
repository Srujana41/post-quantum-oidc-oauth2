import requests

# using intermediate rp
# requests.get("https://172.27.96.243/.well-known/openid-configuration",  verify=f"/home/ubuntu/post-quantum-oidc-oauth2/rp_certs/IntermediaryCAs/bundlecerts_chain_rp_ecdsa.crt")

# using servercerts rp
# requests.get("https://172.27.96.243/.well-known/openid-configuration",  verify=f"/home/ubuntu/post-quantum-oidc-oauth2/rp_certs/ServerCerts/bundlecerts_chain_rp_ecdsa_172.27.96.182.crt")

# using root rp
requests.get("https://172.27.96.243/.well-known/openid-configuration",  verify=f"/home/ubuntu/post-quantum-oidc-oauth2/rp_certs/ServerCerts/root_rp_ecdsa.crt")


# run this command in rp
# requests.get("https://172.27.96.243/.well-known/openid-configuration",  verify=f"/home/ubuntu/op_certs/IntermediaryCAs/bundlecerts_chain_op_ecdsa.crt")