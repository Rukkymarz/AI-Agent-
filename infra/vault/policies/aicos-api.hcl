# API: read its own runtime secrets only. No list on the mount, no write, no sys/*.
path "secret/data/aicos/runtime/*"  { capabilities = ["read"] }
path "secret/data/aicos/plugins/*"  { capabilities = ["read"] }   # PluginContext enforces per-plugin prefixes
path "transit/encrypt/aicos-pii"    { capabilities = ["update"] }
path "transit/decrypt/aicos-pii"    { capabilities = ["update"] }
path "auth/token/renew-self"        { capabilities = ["update"] }
