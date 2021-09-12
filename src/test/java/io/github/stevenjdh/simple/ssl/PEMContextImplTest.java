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

package io.github.stevenjdh.simple.ssl;

import io.github.stevenjdh.simple.exceptions.GenericKeyStoreException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Comparator;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import io.github.stevenjdh.simple.ssl.SimpleSSLContext.KeyStoreType;
import io.github.stevenjdh.support.BaseTestSupport;
import java.lang.reflect.InvocationTargetException;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class PEMContextImplTest extends BaseTestSupport {

    private static Method getKeyStoreMethod;
    private static Method getTrustStoreMethod;
    
    @BeforeAll
    static void setUp() throws Exception {
        getKeyStoreMethod = PEMContextImpl.class.getDeclaredMethod("getKeyStore", 
                KeyStoreType.class, Path.class, 
                char[].class, char[].class, Path.class);
        
        getTrustStoreMethod = PEMContextImpl.class.getDeclaredMethod("getTrustStore", 
                KeyStoreType.class, Path.class);
        
        getKeyStoreMethod.setAccessible(true);
        getTrustStoreMethod.setAccessible(true);
        OUTPUT_DIR.toFile().mkdirs();
    }
    
    @AfterAll
    static void tearDown() throws IOException {
        Files.walk(OUTPUT_DIR)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete);
    }
    
    @Test
    @DisplayName("Should create SSL context and save keystore when loading private key.")
    void Should_CreateSSLContextAndSaveKeyStore_When_LoadingPrivateKey() throws Exception {
        char[] password = "123456".toCharArray();
        var builder = new PEMContextBuilderImpl();
        
        builder.privateKeyPath = CLIENT_KEY.toPath();
        builder.privateKeyCertChainPath = CLIENT_CERT.toPath();
        builder.keyStorePath = KEYSTORE_OUTPUT.toPath();
        builder.keyStorePassword = password;
        
        var ctx = PEMContextImpl.create(builder);
        var ks = KeyStore.getInstance(KeyStoreType.PKCS12.value);
        try ( var inputStream = new FileInputStream(KEYSTORE_OUTPUT)) {
            ks.load(inputStream, password);
        }
        
        assertNotNull(ctx);
        assertEquals("TLSv1.3", ctx.getProtocol());
        assertThat(KEYSTORE_OUTPUT).exists();
        assertEquals(1, ks.size());
        
        KEYSTORE_OUTPUT.delete();
    }
    
    @Test
    @DisplayName("Should create SSL context without saving keystore when loading private key.")
    void Should_CreateSSLContextWithoutSavingKeyStore_When_LoadingPrivateKey() {
        var builder = new PEMContextBuilderImpl();
        builder.privateKeyPath = CLIENT_KEY.toPath();
        builder.privateKeyCertChainPath = CLIENT_CERT.toPath();
        
        var ctx = PEMContextImpl.create(builder);
        
        assertNotNull(ctx);
        assertEquals("TLSv1.3", ctx.getProtocol());
        assertThat(KEYSTORE_OUTPUT).doesNotExist();
    }
    
    @Test
    @DisplayName("Should create SSL context and save truststore when loading certificate chain.")
    void Should_CreateSSLContextAndSaveTrustStore_When_LoadingCertChain() throws Exception {
        char[] password = "123456".toCharArray();
        var builder = new PEMContextBuilderImpl();
        
        builder.publicKeyPath = BADSSL_COM_CHAIN.toPath();
        builder.trustStorePath = TRUSTSTORE_OUTPUT.toPath();
        builder.trustStorePassword = password;
        
        var ctx = PEMContextImpl.create(builder);
        var ks = KeyStore.getInstance(KeyStoreType.PKCS12.value);
        try ( var inputStream = new FileInputStream(TRUSTSTORE_OUTPUT)) {
            ks.load(inputStream, password);
        }
        
        assertNotNull(ctx);
        assertEquals("TLSv1.3", ctx.getProtocol());
        assertThat(TRUSTSTORE_OUTPUT).exists();
        assertEquals(2, ks.size());
        
        TRUSTSTORE_OUTPUT.delete();
    }
    
    @Test
    @DisplayName("Should create SSL context without saving truststore when loading certificate chain.")
    void Should_CreateSSLContextWithoutSavingTrustStore_When_LoadingCertChain() {
        var builder = new PEMContextBuilderImpl();
        builder.publicKeyPath = BADSSL_COM_CHAIN.toPath();
        
        var ctx = PEMContextImpl.create(builder);
        
        assertNotNull(ctx);
        assertEquals("TLSv1.3", ctx.getProtocol());
        assertThat(TRUSTSTORE_OUTPUT).doesNotExist();
    }
    
    @Test
    @DisplayName("Should throw GenericKeyStoreException when password minimum is not met.")
    void Should_ThrowGenericKeyStoreException_When_PasswordMiniumIsNotMet() {
        var builder = new PEMContextBuilderImpl();
        builder.publicKeyPath = BADSSL_COM_CHAIN.toPath();
        builder.trustStorePath = TRUSTSTORE_OUTPUT.toPath();
        builder.trustStorePassword = "123".toCharArray();
        
        GenericKeyStoreException ex = catchThrowableOfType(() -> { 
            PEMContextImpl.create(builder);
        }, GenericKeyStoreException.class);
        
        assertThat(ex).isExactlyInstanceOf(GenericKeyStoreException.class)
                .hasMessageContaining("KeyStore password must contain at least 4 characters.")
                .hasNoCause();
                
        assertThat(TRUSTSTORE_OUTPUT).doesNotExist();
    }
    
    @Test
    @DisplayName("Should throw GenericKeyStoreException when password is null.")
    void Should_ThrowGenericKeyStoreException_When_PasswordIsNull() {
        var builder = new PEMContextBuilderImpl();
        builder.publicKeyPath = BADSSL_COM_CHAIN.toPath();
        builder.trustStorePath = TRUSTSTORE_OUTPUT.toPath();
        builder.trustStorePassword = null;
        
        GenericKeyStoreException ex = catchThrowableOfType(() -> { 
            PEMContextImpl.create(builder);
        }, GenericKeyStoreException.class);
        
        assertThat(ex).isExactlyInstanceOf(GenericKeyStoreException.class)
                .hasMessageContaining("KeyStore password must contain at least 4 characters.")
                .hasNoCause();
                
        assertThat(TRUSTSTORE_OUTPUT).doesNotExist();
    }

    @Test
    @DisplayName("Should create PKCS12 keystore when loading private key.")
    void Should_CreatePKCS12KeyStore_When_LoadingPrivateKey() throws Exception {
        var ks = (KeyStore) getKeyStoreMethod.invoke(PEMContextImpl.class, 
                KeyStoreType.PKCS12, CLIENT_KEY.toPath(), null, 
                null, CLIENT_CERT.toPath());
        
        String alias = "signing-key-alias";
        
        assertEquals(KeyStoreType.PKCS12.value, ks.getType());
        assertEquals(1, ks.size());
        assertTrue(ks.containsAlias(alias));
        assertTrue(ks.isKeyEntry(alias));
        assertFalse(ks.isCertificateEntry(alias));
        assertFalse(ks.containsAlias("0123456789"));
    }
    
    @Test
    @DisplayName("Should create JKS keystore when loading private key.")
    void Should_CreateJKSKeyStore_When_LoadingPrivateKey() throws Exception {
        var ks = (KeyStore) getKeyStoreMethod.invoke(PEMContextImpl.class, 
                KeyStoreType.JKS, CLIENT_KEY.toPath(), new char[0], 
                null, CLIENT_CERT.toPath());
        
        String alias = "signing-key-alias";
        
        assertEquals(KeyStoreType.JKS.value, ks.getType());
        assertEquals(1, ks.size());
        assertTrue(ks.containsAlias("signing-key-alias"));
        assertTrue(ks.isKeyEntry(alias));
        assertFalse(ks.isCertificateEntry(alias));
        assertFalse(ks.containsAlias("0123456789"));
    }
    
    @Test
    @DisplayName("Should throw NullPointerException when using JKS and private key with null password.")
    void Should_ThrowNullPointerException_When_UsingJKSAndPrivateKeyWithNullPasssword() {
        InvocationTargetException ex = catchThrowableOfType(() -> { 
            getKeyStoreMethod.invoke(PEMContextImpl.class, 
                    KeyStoreType.JKS, CLIENT_KEY.toPath(), null, 
                    null, CLIENT_CERT.toPath()); 
        }, InvocationTargetException.class);
        
        assertThat(ex).hasRootCauseExactlyInstanceOf(NullPointerException.class)
                .getRootCause()
                .hasMessage("Cannot read the array length because \"password\" is null");
    }
    
    @Test
    @DisplayName("Should create PKCS12 truststore when loading certificate chain.")
    void Should_CreatePKCS12TrustStore_When_LoadingCertChain() throws Exception {
        var ks = (KeyStore) getTrustStoreMethod.invoke(PEMContextImpl.class,
                KeyStoreType.PKCS12, BADSSL_COM_CHAIN.toPath());
        
        String alias = "69d6dc42a2d60a20cf2b384d3a7763edabc2e144".substring(0, 39);
        
        assertEquals(KeyStoreType.PKCS12.value, ks.getType());
        assertEquals(2, ks.size());
        assertTrue(ks.containsAlias(alias));
        assertTrue(ks.isCertificateEntry(alias));
        assertFalse(ks.containsAlias("0123456789"));
    }
    
    @Test
    @DisplayName("Should create JKS truststore when loading certificate chain.")
    void Should_CreateJKSTrustStore_When_LoadingCertChain() throws Exception {
        var ks = (KeyStore) getTrustStoreMethod.invoke(PEMContextImpl.class, 
                KeyStoreType.JKS, BADSSL_COM_CHAIN.toPath());
        
        String alias = "69d6dc42a2d60a20cf2b384d3a7763edabc2e144".substring(0, 39);
        
        assertEquals(KeyStoreType.JKS.value, ks.getType());
        assertEquals(2, ks.size());
        assertTrue(ks.containsAlias(alias));
        assertTrue(ks.isCertificateEntry(alias));
        assertFalse(ks.containsAlias("0123456789"));
    }
}