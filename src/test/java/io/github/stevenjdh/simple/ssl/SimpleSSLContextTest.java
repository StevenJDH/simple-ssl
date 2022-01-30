/*
 * This file is part of Simple SSL <https://github.com/StevenJDH/simple-ssl>.
 * Copyright (C) 2021-2022 Steven Jenkins De Haro.
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

package io.github.stevenjdh.simple.ssl;

import javax.net.ssl.SSLContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import io.github.stevenjdh.simple.exceptions.GenericKeyStoreException;
import io.github.stevenjdh.simple.ssl.SimpleSSLContext.KeyStoreType;
import io.github.stevenjdh.support.BaseTestSupport;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;
import java.util.Comparator;
import javax.crypto.BadPaddingException;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class SimpleSSLContextTest extends BaseTestSupport {
    
    @Test
    @DisplayName("Should return needed string representation for keystore types.")
    void Should_ReturnNeededStringRepresentation_ForKeyStoreTypes() {
        var pkcs12 = KeyStoreType.PKCS12;
        var jks = KeyStoreType.JKS;
        
        assertEquals("PKCS12", pkcs12.value);
        assertEquals("PKCS12", pkcs12.toString());
        assertEquals("JKS", jks.value);
        assertEquals("JKS", jks.toString());
    }
    
    @Test
    @DisplayName("Should return default SSL context when not building SSL context.")
    void Should_ReturnDefaultSSLContext_When_NotBuildingSSLContext() {
        var ctx = SimpleSSLContext.newSSLContext();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should return default SSL context when building directly.")
    void Should_ReturnDefaultSSLContext_When_BuildingDirectly() {
        var ctx = SimpleSSLContext.newBuilder().build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should return truststore only SSL context when truststore is only provided.")
    void Should_ReturnTrustStoreOnlySSLContext_When_TrustStoreIsOnlyProvided() {
        var ctx = SimpleSSLContext.newBuilder()
                .withTrustStore(CLIENT_TRUSTSTORE.toPath(), "test123456".toCharArray())
                .trustStoreType(KeyStoreType.PKCS12)
                .build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should return keystore only SSL context when keystore is only provided.")
    void Should_ReturnKeyStoreOnlySSLContext_When_KeyStoreIsOnlyProvided() {
        var ctx = SimpleSSLContext.newBuilder()
                .withKeyStore(CLIENT_KEYSTORE.toPath(), "test".toCharArray())
                .keyStoreType(KeyStoreType.PKCS12)
                .build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should return full SSL context when truststore and keystore are provided.")
    void Should_ReturnFullSSLContext_When_TrustStoreAndKeyStoreAreProvided() {
        var ctx = SimpleSSLContext.newBuilder()
                .withTrustStore(CLIENT_TRUSTSTORE.toPath(), "test123456".toCharArray())
                .withKeyStore(CLIENT_KEYSTORE.toPath(), "test".toCharArray())
                .build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should throw UncheckedIOException for incorrect password.")
    void Should_ThrowUncheckedIOException_ForIncorrectPassword() {
        UncheckedIOException ex = catchThrowableOfType(() -> { 
            SimpleSSLContext.newBuilder()
                    .withTrustStore(CLIENT_TRUSTSTORE.toPath(), "badpass".toCharArray())
                    .build(); 
        }, UncheckedIOException.class);
        
        assertThat(ex).hasMessage("keystore password was incorrect")
                .hasCauseExactlyInstanceOf(IOException.class)
                .getCause().hasMessage("keystore password was incorrect")
                .hasRootCauseExactlyInstanceOf(UnrecoverableKeyException.class)
                .getRootCause().hasMessageStartingWith("failed to decrypt safe contents entry");
    }
    
    @Test
    @DisplayName("Should throw GenericKeyStoreException when building PEM context directly.")
    void Should_ThrowGenericKeyStoreException_When_BuildingPEMContextDirectly() {
        assertThatThrownBy(() -> SimpleSSLContext.newPEMContextBuilder().build())
                .isExactlyInstanceOf(GenericKeyStoreException.class)
                .hasMessage("No certificate or private key paths were specified.")
                .isInstanceOf(RuntimeException.class);
    }
    
    @Test
    @DisplayName("Should return truststore only SSL context when public key is only provided.")
    void Should_ReturnTrustStoreOnlySSLContext_When_PublicKeyIsOnlyProvided() {
        var ctx = SimpleSSLContext.newPEMContextBuilder()
                .withPublicKey(WIREMOCK_CERT.toPath())
                .trustStoreType(KeyStoreType.PKCS12)
                .build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should return keystore only SSL context when private key is only provided.")
    void Should_ReturnKeyStoreOnlySSLContext_When_PrivateKeyIsOnlyProvided() {
        var ctx = SimpleSSLContext.newPEMContextBuilder()
                .withPrivateKey(CLIENT_KEY.toPath(), CLIENT_CERT.toPath())
                .keyStoreType(KeyStoreType.PKCS12)
                .build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should return keystore only SSL context when encrypted private key is only provided.")
    void Should_ReturnKeyStoreOnlySSLContext_When_EncryptedPrivateKeyIsOnlyProvided() {
        var ctx = SimpleSSLContext.newPEMContextBuilder()
                .withPrivateKey(CLIENT_ENCRYPTED_KEY.toPath(), CLIENT_CERT.toPath())
                .withPrivateKeyPassword("test".toCharArray())
                .build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should throw GenericKeyStoreException for incorrect private key password.")
    void Should_ThrowGenericKeyStoreException_ForIncorrectPrivateKeyPassword() {
        GenericKeyStoreException ex = catchThrowableOfType(() -> { 
            SimpleSSLContext.newPEMContextBuilder()
                    .withPrivateKey(CLIENT_ENCRYPTED_KEY.toPath(), CLIENT_CERT.toPath())
                    .withPrivateKeyPassword("badpass".toCharArray())
                    .build(); 
        }, GenericKeyStoreException.class);
        
        assertThat(ex).hasRootCauseExactlyInstanceOf(BadPaddingException.class)
                .getRootCause()
                .hasMessageStartingWith("Given final block not properly padded");
    }
    
    @Test
    @DisplayName("Should throw GenericKeyStoreException when missing encrypted private key password.")
    void Should_ThrowGenericKeyStoreException_When_MissingEncryptedPrivateKeyPassword() {
        GenericKeyStoreException ex = catchThrowableOfType(() -> { 
            SimpleSSLContext.newPEMContextBuilder()
                    .withPrivateKey(CLIENT_ENCRYPTED_KEY.toPath(), CLIENT_CERT.toPath())
                    .build(); 
        }, GenericKeyStoreException.class);
        
        assertThat(ex).hasRootCauseExactlyInstanceOf(InvalidKeyException.class)
                .getRootCause()
                .hasMessageContaining("DerValue.getBigIntegerInternal, not expected 48");
    }
    
    @Test
    @DisplayName("Should return full SSL context when private and public keys are provided.")
    void Should_ReturnFullSSLContext_When_PrivateAndPublicKeysAreProvided() {
        var ctx = SimpleSSLContext.newPEMContextBuilder()
                .withPrivateKey(CLIENT_KEY.toPath(), CLIENT_CERT.toPath())
                .withPublicKey(WIREMOCK_CERT.toPath())
                .build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should save keystore and truststore for provided private and public keys.")
    void Should_SaveKeyStoreAndTrustStore_ForProvidedPrivateAndPublicKeys() throws Exception {
        OUTPUT_DIR.toFile().mkdirs();
        
        var ctx = SimpleSSLContext.newPEMContextBuilder()
                .withPrivateKey(CLIENT_KEY.toPath(), CLIENT_CERT.toPath())
                .withPublicKey(WIREMOCK_CERT.toPath())
                .saveKeyStore(KEYSTORE_OUTPUT.toPath(), "123456".toCharArray())
                .saveTrustStore(TRUSTSTORE_OUTPUT.toPath(), "123456".toCharArray())
                .build();
        
        assertNotNull(ctx);
        assertThat(ctx).isExactlyInstanceOf(SSLContext.class);
        assertThat(KEYSTORE_OUTPUT).exists();
        assertThat(TRUSTSTORE_OUTPUT).exists();
        
        Files.walk(OUTPUT_DIR)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete);
    }

    @Test
    @DisplayName("Should return build info when git.properties is present.")
    void Should_ReturnBuildInfo_When_GitPropertiesIsPresent() throws Exception {
        var pom = new MavenXpp3Reader();
        Model model;

        try (var fr = new FileReader("pom.xml", StandardCharsets.UTF_8)) {
            model = pom.read(fr);
        }

        assertThat(getClass().getClassLoader().getResource("git.properties")).isNotNull();
        assertEquals(model.getVersion(), SimpleSSLContext.getBuildInfo().getGitBuildVersion());
    }
}