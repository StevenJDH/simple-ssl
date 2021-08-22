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

import io.github.stevenjdh.simple.ssl.SimpleSSLContext.KeyStoreType;
import io.github.stevenjdh.support.BaseTestSupport;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;

public class SimpleSSLContextImplTest extends BaseTestSupport {
    
    private static Method getKeyStoreMethod;
    
    @BeforeAll
    static void setUp() throws Exception {
        getKeyStoreMethod = SimpleSSLContextImpl.class.getDeclaredMethod("getKeyStore", 
                KeyStoreType.class, Path.class, char[].class);
        getKeyStoreMethod.setAccessible(true);
    }
    
    @Test
    @DisplayName("Should successfully load PKCS12 keystore for specified file.")
    void Should_SuccessfullyLoadPKCS12KeyStore_ForSpecifiedFile() throws Exception {
        var ks = (KeyStore) getKeyStoreMethod.invoke(SimpleSSLContextImpl.class, 
                KeyStoreType.PKCS12, BADSSL_TRUSTSTORE_PKCS12.toPath(), "test".toCharArray());
        
        String alias = "untrusted-root-badssl-certificate";
        
        assertEquals(KeyStoreType.PKCS12.value, ks.getType());
        assertEquals(1, ks.size());
        assertTrue(ks.containsAlias(alias));
        assertTrue(ks.isCertificateEntry(alias));
        assertFalse(ks.containsAlias("0123456789"));
    }
    
    @Test
    @DisplayName("Should successfully load JKS keystore for specified file.")
    void Should_SuccessfullyLoadJKSKeyStore_ForSpecifiedFile() throws Exception {
        var ks = (KeyStore) getKeyStoreMethod.invoke(PEMContextImpl.class, 
                KeyStoreType.JKS, BADSSL_TRUSTSTORE_JKS.toPath(), "test123456".toCharArray());
        
        String alias = "untrusted-root-badssl-certificate";
        
        assertEquals(KeyStoreType.JKS.value, ks.getType());
        assertEquals(1, ks.size());
        assertTrue(ks.containsAlias(alias));
        assertTrue(ks.isCertificateEntry(alias));
        assertFalse(ks.containsAlias("0123456789"));
    }
}