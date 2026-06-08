// Legacy billing exporter — still deployed in the mainframe bridge.
package com.example.billing;

import java.security.KeyPairGenerator;

public class BillingSigner {
    // DSA signing of nightly billing batches.
    public void init() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        // SignatureAlgorithm.DSA applied to each batch header.
    }

    // AES-128 protecting exported invoice archives.
    public static final String CIPHER = "aes-128-cbc";
}
