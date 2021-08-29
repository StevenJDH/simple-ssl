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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import io.github.stevenjdh.simple.exceptions.GenericKeyStoreException;
import java.nio.file.Path;
import java.security.UnrecoverableKeyException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;

final class SimpleSSLContextImpl implements SimpleSSLContext {

    private final Path keyStorePath;
    private final char[] keyStorePassword;
    private final Path trustStorePath;
    private final char[] trustStorePassword;
    private final KeyStoreType keyStoreType;
    private final KeyStoreType trustStoreType;
    private final SSLContext sslContext;
    
    static SSLContext create(SSLContextBuilderImpl builder) {
        return new SimpleSSLContextImpl(builder).getSSLContext();
    }
    
    private SimpleSSLContextImpl(SSLContextBuilderImpl builder) {
        keyStorePath = builder.keyStorePath;
        keyStorePassword = builder.keyStorePassword;
        trustStorePath = builder.trustStorePath;
        trustStorePassword = builder.trustStorePassword;
        keyStoreType = builder.keyStoreType;
        trustStoreType = builder.trustStoreType;
        
        if (builder.keyStorePath == null && builder.trustStorePath == null) {
            try {
                sslContext = SSLContext.getDefault();
            } catch (NoSuchAlgorithmException ex) {
                throw new GenericKeyStoreException(ex.getMessage(), ex);
            }
        } else {
            sslContext = createSSLContext();
        }
    }

    SSLContext getSSLContext() {
        return sslContext;
    }
    
    private SSLContext createSSLContext() {
        try {
            var keyManagers = getKeyManagers(keyStoreType, keyStorePath, keyStorePassword);
            var trustManagers = getTrustManagers(trustStoreType, trustStorePath, trustStorePassword);
            var context = SSLContext.getInstance("TLSv1.3");
            context.init(keyManagers, trustManagers, new SecureRandom());
            
            return context;
        } catch (GeneralSecurityException ex) {
            throw new GenericKeyStoreException(ex.getMessage(), ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex.getMessage(), ex);
        }
    }
    
    private static KeyManager[] getKeyManagers(KeyStoreType storeType, Path storePath, 
            char[] storePassword) throws NoSuchAlgorithmException, KeyStoreException, 
            IOException, CertificateException, UnrecoverableKeyException {
        
        if (storePath == null) {
            return new KeyManager[0];
        }
        
        var kmf = KeyManagerFactory.getInstance("SunX509");
        var keyStore = getKeyStore(storeType, storePath, storePassword);
        kmf.init(keyStore, storePassword);
        
        return kmf.getKeyManagers();
    }
    
    private static TrustManager[] getTrustManagers(KeyStoreType storeType, Path storePath, 
            char[] storePassword) throws NoSuchAlgorithmException, KeyStoreException, 
            IOException, CertificateException {
        
        if (storePath == null) {
            return new TrustManager[0];
        }
        
        var tmf = TrustManagerFactory.getInstance("SunX509");
        var trustStore = getKeyStore(storeType, storePath, storePassword);
        tmf.init(trustStore);
        
        return tmf.getTrustManagers();
    }
    
    private static KeyStore getKeyStore(KeyStoreType storeType, Path storePath, char[] storePassword) 
            throws KeyStoreException, IOException, NoSuchAlgorithmException, 
            CertificateException {

        var ks = KeyStore.getInstance(storeType.value);

        try ( var inputStream = new FileInputStream(storePath.toFile())) {
            ks.load(inputStream, storePassword);
        }

        return ks;
    }
}