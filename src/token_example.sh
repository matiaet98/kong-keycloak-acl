access_token=`curl -X POST -k --silent -H 'Content-Type: application/x-www-form-urlencoded' 'https://keycloak:8443/auth/realms/development/protocol/openid-connect/token' \
--data 'username=mati&password=faklmo09.&client_id=test-app-2&grant_type=password&client_secret=2bf49731-9540-45e8-baae-529ab64c8b89' | jq -r .access_token`

curl -X POST -k --silent \
'https://keycloak:8443/auth/realms/development/protocol/openid-connect/token' \
-H "Authorization: Bearer ${access_token}" \
--data "audience=test-app-2" \
--data "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket"

  curl -X POST \
  https://${host}:${port}/auth/realms/${realm}/protocol/openid-connect/token \
  -H "Authorization: Bearer ${access_token}" \
  --data "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket" \
  --data "audience={resource_server_client_id}"

  curl -X POST \
  https://${host}:${port}/auth/realms/${realm}/protocol/openid-connect/token \
  -H "Authorization: Bearer ${access_token}" \
  --data "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket" \
  --data "ticket=${permission_ticket}

curl -X POST -k -H 'Content-Type: application/x-www-form-urlencoded' -i 'https://keycloak:8443/auth/realms/development/protocol/openid-connect/token' \
--data 'username=mati&password=faklmo09.&client_id=test-app-2&grant_type=password&client_secret=2bf49731-9540-45e8-baae-529ab64c8b89'

curl -X POST \
  https://${host}:${port}/auth/realms/${realm}/protocol/openid-connect/token \
  -H "Authorization: Bearer ${access_token}" \
  --data "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket" \
  --data "audience={resource_server_client_id}" \
  --data "permission=Resource A#Scope A" \
  --data "permission=Resource B#Scope B"

  curl -X POST \
  https://${host}:${port}/auth/realms/${realm}/protocol/openid-connect/token \
  -H "Authorization: Bearer ${access_token}" \
  --data "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket" \
  --data "audience={resource_server_client_id}"

  curl -X POST \
  https://${host}:${port}/auth/realms/${realm}/protocol/openid-connect/token \
  -H "Authorization: Bearer ${access_token}" \
  --data "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket" \
  --data "ticket=${permission_ticket}