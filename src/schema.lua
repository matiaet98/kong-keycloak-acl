local typedefs = require "kong.db.schema.typedefs"

return {
    name = "kong-keycloak-acl",
    fields = {
        { consumer = typedefs.no_consumer },
        { config = {
            type = "record",
            fields = {
                { token_endpoint = { type = "string", required = true }, },
                { audience = { type = "string", required = true }, },
                { resource = { type = "string", required = false }, },
                { scope = { type = "string", required = false }, },
            }
        }
        }
    },
    entity_checks = {
        { at_least_one_of = {"config.scope", "config.resource"}, },
    },
}