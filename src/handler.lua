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

    local audience = plugin_conf.audience
    local token_endpoint = plugin_conf.token_endpoint
    local access_token = Get_access_token()
    local uri = ngx.var.request_uri

    if Authorized(token_endpoint, audience, access_token, uri) then
        return true
    else
        ngx.log(ngx.DEBUG, "Unauthorized request from ip "..ngx.req.get_headers()['X-Real-Ip'])
        ngx.status = 401
        ngx.say("Unauthorized")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

end

function Get_access_token()
    --This header is setted in nokia plugin "oidc". Without this, the plugins won't work
    return ngx.req.get_headers()['X-Access-Token']
end

function Authorized(token_endpoint, audience, access_token, uri)
    local httpc = http.new()
    local res, error = httpc:request_uri(token_endpoint, {
        method = "POST",
        ssl_verify = false, --total, ya lo deberia haber verificado el oidc
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
            ["Authorization"] = "Bearer " .. access_token
        },
        body = {
            audience = audience,
            grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket",
            uri = uri
        }
    })
    if not res then
        ngx.log(ngx.ERROR, error)
        return false
    end

    local parsed_res = cjson_s.decode(res.body)
    if not parsed_res then
        ngx.log(ngx.ERROR, "Error parsing json response")
        return false
    end

    if not parsed_res.error then
        return true
    end
    return false

end

return ACL
