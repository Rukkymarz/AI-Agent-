# Human break-glass. Usage is alerted on via the Vault audit device -> SIEM.
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
