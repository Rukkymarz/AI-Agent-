path "secret/data/aicos/runtime/worker/*"      { capabilities = ["read"] }
path "secret/data/aicos/integrations/*"         { capabilities = ["read"] }
path "auth/token/renew-self"                    { capabilities = ["update"] }
