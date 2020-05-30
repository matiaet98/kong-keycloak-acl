--[[
@Author: Matias Estevez - mestevez@afip.gob.ar
]]

local ACL = require("kong.plugins.base_plugin"):extend()
local cjson_s = require("cjson.safe")
local http = require("resty.http")
local ngx = ngx

ACL.PRIORITY = 950

function ACL:new()
    ACL.super.new(self, "kong-keycloak-acl")
end


function ACL:access(plugin_conf)
    ACL.super.access(self)

    local token_endpoint = plugin_conf.token_endpoint
    local audience = plugin_conf.audience
    local resource = plugin_conf.resource
    local scope = plugin_conf.scope
    local access_token = get_access_token()

    if is_authorized(
        token_endpoint,
        audience,
        resource,
        scope,
        access_token) then
        ngx.log(ngx.INFO, "Acces granted to "..access_token.." with audience "..audience)
        return --esta todo bien
    else
        ngx.log(ngx.WARN, "Unauthorized request from access token "..access_token.." with audience "..audience)
        ngx.status = 401
        ngx.say("Unauthorized")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
end


function get_access_token()
    --This header is setted in nokia plugin "oidc". Without this, the plugins won't work
    local headers = ngx.req.get_headers()
    local authorization_header = headers['Authorization']
    local access_token_header = headers['X-Access-Token']
    local access_token = nil

    if authorization_header ~= nil then
        access_token = auth_header_to_access_token(authorization_header)
        if access_token == nil then
            ngx.log(ngx.INFO, "Corrupt request")
            ngx.status = 400
            ngx.say("Bad request - Authorization header is corrupt")
            ngx.exit(ngx. HTTP_BAD_REQUEST)
        end
        return access_token
    end

    if access_token_header ~= nil then
        access_token = access_token_header
        return access_token
    end

    ngx.log(ngx.INFO, "Cannot get access token")
    ngx.status = 401
    ngx.say("Unauthorized")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

function auth_header_to_access_token(auth_header)
    local divider = auth_header:find(' ')
    if string.lower(auth_header:sub(0, divider - 1)) ~= string.lower("Bearer") then
        ngx.log(ngx.INFO, "Cannot get access token")
        ngx.status = 401
        ngx.say("Unauthorized")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
    return auth_header:sub(divider + 1)
end

function build_permission_string(resource, scope)
    if(scope == nil) then
        return resource
    end
    if(resource == nil) then
        return scope
    end
    return resource.."#"..scope
end

function is_authorized(token_endpoint, audience, resource, scope, access_token)
    local httpc = http.new()
    local body = {}
    body.audience = audience
    body.grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket"
    body.permission = build_permission_string(resource, scope)

    local res, error = httpc:request_uri(token_endpoint, {
        method = "POST",
        ssl_verify = false, --total, ya lo deberia haber verificado el oidc
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
            ["Authorization"] = "Bearer " .. access_token
        },
        body = ngx.encode_args(body)
    })

    if not res then
        ngx.log(ngx.WARN, error)
        ngx.status = 500
        ngx.say("Network error")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    if res.status ~= 200 then
        return false
    end

    local parsed_res = cjson_s.decode(res.body)
    if not parsed_res then
        ngx.log(ngx.WARN, "Internal server errorrr")
        ngx.status = 500
        ngx.say("Error parsing json")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    if parsed_res.result == "true" then
        return true
    end

    return false

end

return ACL
