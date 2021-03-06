package = "kong-keycloak-acl"
version = "1.1.0-0"
source = {
   url = "git+https://github.com/matiaet98/kong-keycloak-acl.git",
   tag = "master",
   dir = "kong-keycloak-acl"
}
description = {
   summary = "A plugin for Kong which enforces Keycloak defined authorization policies",
   detailed = [[This plugins runs after kong-oidc (https://github.com/nokia/kong-oidc) using its generated access token to enforce Keycloak resource authorization policies]],
   homepage = "https://github.com/matiaet98/kong-keycloak-acl.git",
   license = "Apache 2.0"
}
dependencies = {}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.kong-keycloak-acl.handler"]  = "src/handler.lua",
      ["kong.plugins.kong-keycloak-acl.schema"]= "src/schema.lua"
   }
}
