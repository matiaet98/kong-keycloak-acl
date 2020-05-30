response1=`curl -k -L --silent --location --request POST 'https://keycloak:8443/auth/realms/development/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=user1' \
--data-urlencode 'password=user1' \
--data-urlencode 'client_id=test-app1'`

 access_token=`echo ${response1} | jq -r .access_token`

echo ${response1}
echo "---------------------------------------------------------------------"

response2=`curl -k -L -i --silent --location --request POST 'https://keycloak:8443/auth/realms/development/protocol/openid-connect/token' \
--header "Authorization: Bearer ${access_token}" \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:uma-ticket' \
--data-urlencode 'response_mode=decision' \
--data-urlencode 'audience=kong' \
--data-urlencode 'permission=urn:kong:resources:test#test-app1:edit'`

echo ${response2}
