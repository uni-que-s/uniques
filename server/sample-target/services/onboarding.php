<?php
// Tenant onboarding — provisions an RSA keypair per customer.

function provision_tenant_key() {
    // RSA-2048 keypair used to encrypt the tenant's data-export bundles.
    $key = openssl_pkey_new(["private_key_bits" => 2048, "private_key_type" => OPENSSL_KEYTYPE_RSA]);
    return $key;
}
