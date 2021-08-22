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

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import io.github.stevenjdh.simple.security.cert.CertUtil.HashType;
import io.github.stevenjdh.support.BaseTestSupport;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;

class CertUtilTest extends BaseTestSupport {

    private static CertificateFactory certificateFactoryX509;
    private static KeyFactory keyFactoryRSA;
    
    @BeforeAll
    static void setUp() throws Exception {
        certificateFactoryX509 = CertificateFactory.getInstance("X.509");
        keyFactoryRSA = KeyFactory.getInstance("RSA");
    }
    
    @Test
    @DisplayName("Should return needed string representation for hash types.")
    void Should_ReturnNeededStringRepresentation_ForHashTypes() {
        var md5 = HashType.MD5;
        var sha1 = HashType.SHA_1;
        var sha256 = HashType.SHA_256;

        assertEquals("MD5", md5.value);
        assertEquals("MD5", md5.toString());
        assertEquals("SHA-1", sha1.value);
        assertEquals("SHA-1", sha1.toString());
        assertEquals("SHA-256", sha256.value);
        assertEquals("SHA-256", sha256.toString());
    }

    @Test
    @DisplayName("Should return PEM formatted cert when converted from DER format.")
    void Should_ReturnPEMFormatedCert_When_ConvertedFromDERFormat() throws Exception {
        String expectedPEM = CertUtil.resetEOL(Files.readString(CLIENT_CERT.toPath()));
        X509Certificate cert;

        try ( var is = new ByteArrayInputStream(expectedPEM.getBytes())) {
            cert = (X509Certificate) certificateFactoryX509.generateCertificate(is);
        }

        String actualPEM = CertUtil.toPEMCertificate(cert.getEncoded());

        assertThat(actualPEM).isEqualTo(expectedPEM.strip());
    }
    
    @Test
    @DisplayName("Should return PEM formatted key when converted from DER format.")
    void Should_ReturnPEMFormatedKey_When_ConvertedFromDERFormat() throws Exception {
        String expectedPEM = CertUtil.resetEOL(Files.readString(CLIENT_KEY.toPath()));
        
        byte[] derFormat = CertUtil.toDERPrivateKey(expectedPEM);
        var keySpec = new PKCS8EncodedKeySpec(derFormat);
        var key = (RSAPrivateKey) keyFactoryRSA.generatePrivate(keySpec);
        String actualPEM = CertUtil.toPEMPrivateKey(key.getEncoded());

        assertThat(actualPEM).isEqualTo(expectedPEM.strip());
    }

    @Test
    @DisplayName("Should match thumbprint for all supported hash types.")
    void Should_MatchThumbprint_ForAllSupportedHashTypes() throws Exception {
        var derData = Files.readAllBytes(UNTRUSTED_ROOT_BADSSL_COM.toPath());
        X509Certificate cert;

        try ( var is = new ByteArrayInputStream(derData)) {
            cert = (X509Certificate) certificateFactoryX509.generateCertificate(is);
        }

        String md5 = CertUtil.getThumbprint(cert, ":", HashType.MD5);
        String sha1 = CertUtil.getThumbprint(cert, ":", HashType.SHA_1);
        String sha256 = CertUtil.getThumbprint(cert, ":", HashType.SHA_256);

        assertEquals("A9:11:B8:3A:0E:DE:8B:A2:D3:7E:27:3D:20:7C:56:E4", md5);
        assertEquals("69:D6:DC:42:A2:D6:0A:20:CF:2B:38:4D:3A:77:63:ED:AB:C2:E1:44", sha1);
        assertEquals("E8:78:C9:44:2C:0F:46:FC:BD:9E:2E:73:7D:21:59:E1:A7:2F:29:FD:D9:56:0D:55:1F:7E:FD:67:18:30:C0:9B", sha256);
    }
}