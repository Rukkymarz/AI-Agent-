# Vault server (single node, integrated raft). For HA use 3-5 nodes + auto-unseal (KMS/HSM).
ui            = false
disable_mlock = false
storage "raft" {
  path    = "/vault/data"
  node_id = "vault-1"
}
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/tls.crt"
  tls_key_file  = "/vault/tls/tls.key"
  tls_min_version = "tls12"
}
api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"
telemetry { disable_hostname = true  prometheus_retention_time = "30s" }
