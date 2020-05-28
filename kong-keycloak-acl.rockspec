package = "kong-keycloak-acl"
version = "0.0.4-0"
source = {
   url = "git+https://github.com/matiaet98/kong-keycloak-acl.git"
}
description = {
   summary = "A plugin for Kong which enforces Keycloak defined authorization policies",
   detailed = [[This plugins runs after kong-oidc (https://github.com/nokia/kong-oidc) using its generated access token and provided audience to enforce Keycloak resource authorization]],
   homepage = "https://github.com/matiaet98/kong-keycloak-acl.git",
   license = "Apache 2.0"
}
dependencies = {
    "kong-oidc ~> 1.1.0-0"
}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.kong-keycloak-acl.handler"]  = "src/handler.lua",
      ["kong.plugins.kong-keycloak-acl.schema"]= "src/schema.lua"
   }
}
