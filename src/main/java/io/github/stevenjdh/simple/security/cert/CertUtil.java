/*
 * This file is part of Simple SSL <https://github.com/StevenJDH/simple-ssl>.
 * Copyright (C) 2021 Steven Jenkins De Haro.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.stevenjdh.simple.security.cert;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertUtil {
    
    private CertUtil() {}

    public static String toPEMCertificate(byte[] derCert) {
        var sb = new StringBuilder();
        
        sb.append("-----BEGIN CERTIFICATE-----").append(System.lineSeparator());
        sb.append(encode(derCert, 64));
        sb.append("-----END CERTIFICATE-----");

        return sb.toString();
    }
    
    public static String toPEMPrivateKey(byte[] derKey) {
        var sb = new StringBuilder();
        
        sb.append("-----BEGIN PRIVATE KEY-----").append(System.lineSeparator());
        sb.append(encode(derKey, 64));
        sb.append("-----END PRIVATE KEY-----");

        return sb.toString();
    }
    
    private static String encode(byte[] derCert, int insertLineBreaks) {
        var sb = new StringBuilder();
        String data = Base64.getEncoder().encodeToString(derCert);

        // Outputs as Base64 with line breaks at every N characters.
        for (var i = 0; i < data.length(); i += insertLineBreaks) {
            sb.append(data.substring(i, Math.min(i + insertLineBreaks, data.length())))
                    .append(System.lineSeparator());
        }

        return sb.toString();
    }
    
    /**
     * Converts a supported private key to DER format to make it easier to use.
     * <p>
     * <b>Note:</b> PKCS#8 and PKCS#1 private keys use different tags, but both use the 
     * PKCS#8 format for their bodies. SSLeay formatted private keys use the same 
     * PKCS#1 tag containing 'RSA' in them, but this format is not supported.
     * </p>
     * <p>
     * <b>Command:</b><br>
     * <code>openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.der -nocrypt</code>
     * </p>
     * @param key Base64 encoded private key in either PKCS#8 or PKCS#1 format.
     * @return Private key in DER format.
     */
    public static byte[] toDERPrivateKey(String key) {
        String parsedBody = key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                // Unicode aware version similar to '\s', \p{Space}, \p{Z}, and \p{C}.
                .replaceAll("\\p{Cc}", "");
        
        return Base64.getDecoder().decode(parsedBody);
    }
    
    public enum HashType {
        MD5("MD5"),
        SHA_1("SHA-1"),
        SHA_256("SHA-256");
        
        public final String value;
        HashType(String type) { value = type; }
        
        @Override
        public String toString() {
            return value;
        }
    }
    
    /**
     * Gets the thumbprint of a certificate using either MD5, SHA-1, or SHA-256.
     * <p>
     * <b>Command:</b><br>
     * <code>openssl x509 -noout -fingerprint -sha256 -inform pem -in certificate.pem</code>
     * </p>
     * @param cert The certificate to use for generating the thumbprint.
     * @param separator A character or empty string to use for the thumbprint separator.
     * @param type Hashing algorithm to to use for thumbprint.
     * @return Thumbprint of certificate using the specified hashing algorithm.
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException 
     */
    public static String getThumbprint(X509Certificate cert, String separator, HashType type) 
            throws NoSuchAlgorithmException, CertificateEncodingException {
        var md = MessageDigest.getInstance(type.value);
        md.update(cert.getEncoded());
        return toHexadecimalString(md.digest(), separator);
    }
 
    private static String toHexadecimalString(byte[] bytes, String separator) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        var sb = new StringBuilder(bytes.length * 3);
        
        for (var aByte : bytes) {
            sb.append(hexDigits[(aByte & 0xf0) >> 4]);
            sb.append(hexDigits[aByte & 0x0f]);
            sb.append(separator);
        }
        
        return sb.substring(0, sb.length() - 1); // Removes trailing separator.
    }
    
    public static String resetEOL(String data) {
        return data.replaceAll("[\\r\\n]+", System.lineSeparator());
    }
}