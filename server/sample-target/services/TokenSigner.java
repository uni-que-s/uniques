// Session token signer — mints RSA-signed JWTs for the API gateway.
package com.example.tokens;

import java.security.KeyPairGenerator;

public class TokenSigner {
    // RSA-2048 keypair backing the JWT signing key.
    public void init() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }
}
