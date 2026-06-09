# Document signing service — issues per-tenant signing keys.
require "openssl"

# RSA-2048 signs outbound webhook payloads.
def webhook_signing_key
  OpenSSL::PKey::RSA.new(2048)
end

# Legacy DSA key still trusted by older partner integrations.
def partner_dsa_key
  OpenSSL::PKey::DSA.new(1024)
end

# ECDSA on the audit trail for tamper-evident receipts.
def receipt_curve_key
  OpenSSL::PKey::EC.new("prime256v1")
end
