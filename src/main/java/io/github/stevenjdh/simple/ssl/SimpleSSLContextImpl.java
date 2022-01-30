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

/**
 * Simple SSLContext implementation. Contains all configuration information 
 * needed to build a custom context.
 * 
 * @since 1.0
 */
final class SimpleSSLContextImpl implements SimpleSSLContext {

    private final Path keyStorePath;
    private final char[] keyStorePassword;
    private final Path trustStorePath;
    private final char[] trustStorePassword;
    private final KeyStoreType keyStoreType;
    private final KeyStoreType trustStoreType;
    private final SSLContext sslContext;
    
    /**
     * Creates a {@link SSLContext} instance that is initialized with an 
     * optional set of key and trust managers, and a source of secure random 
     * bytes.
     * 
     * <p><b>Note:</b> The {@code SSLContext} will use TLS v1.3 by default.
     * 
     * @param builder The configuration needed to build a {@code SSLContext}.
     * @return A new {@code SSLContext} instance.
     */
    static SSLContext create(SSLContextBuilderImpl builder) {
        return new SimpleSSLContextImpl(builder).getSSLContext();
    }
    
    /**
     * Sets the initial state collected from the builder that will be used to 
     * create a custom {@link SSLContext}.
     * 
     * <p><b>Note:</b> Depending on the configuration provided to the builder, 
     * the {@linkplain SSLContext#getDefault() default context} may be returned.
     * 
     * @param builder The configuration needed to build a {@code SSLContext}.
     * 
     * @throws GenericKeyStoreException If one of various keystore related 
     *         issues occur.
     */
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

    /**
     * Gets the stored {@link SSLContext} instance that was created via the 
     * builder.
     * 
     * @return The {@code SSLContext} instance. 
     */
    SSLContext getSSLContext() {
        return sslContext;
    }
    
    /**
     * Creates a {@link SSLContext} instance that is initialized with an 
     * optional set of key and trust managers, and a source of secure random 
     * bytes.
     * 
     * <p><b>Note:</b> The {@code SSLContext} will use TLS v1.3 by default.
     * 
     * @return A new {@code SSLContext} instance.
     * 
     * @throws GenericKeyStoreException If one of various keystore related 
     *         issues occur.
     * @throws UncheckedIOException If there was an I/O problem with reading 
     *         keystore related data.
     */
    private SSLContext createSSLContext() {
        try {
            var keyManagers = getKeyManagers();
            var trustManagers = getTrustManagers();
            var context = SSLContext.getInstance("TLSv1.3");
            context.init(keyManagers, trustManagers, new SecureRandom());
            
            return context;
        } catch (GeneralSecurityException ex) {
            throw new GenericKeyStoreException(ex.getMessage(), ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex.getMessage(), ex);
        }
    }
    
    /**
     * Initializes a key manager factory with a source of provider-specific key 
     * material, and returns one key manager for each type of key material.
     * 
     * @return The key managers for the keystore.
     * 
     * @throws IOException If there is an I/O or format problem with the 
     *         keystore data, if a password is required but not given, or if the 
     *         given password was incorrect. If the error is due to a wrong 
     *         password, the {@link Throwable#getCause cause} of the 
     *         {@code IOException} should be an 
     *         {@code UnrecoverableKeyException}.
     * @throws NoSuchAlgorithmException If no {@code Provider} supports a 
     *         {@code KeyManagerFactorySpi} implementation for the specified 
     *         algorithm, or if the specified algorithm is not available from 
     *         the specified provider, or if the algorithm used to check the 
     *         integrity of the keystore cannot be found.
     * @throws KeyStoreException If no {@code Provider} supports a 
     *         {@code KeyStoreSpi} implementation for the specified type, or if 
     *         the key manager initialization operation fails.
     * @throws CertificateException If any of the certificates in the keystore 
     *         could not be loaded.
     * @throws UnrecoverableKeyException If the key cannot be recovered (e.g. 
     *         the given password is wrong).
     */
    private KeyManager[] getKeyManagers() 
            throws IOException, NoSuchAlgorithmException, KeyStoreException, 
                   CertificateException, UnrecoverableKeyException {
        
        if (keyStorePath == null) {
            return new KeyManager[0];
        }
        
        var kmf = KeyManagerFactory.getInstance("SunX509");
        var keyStore = getKeyStore(keyStoreType, keyStorePath, keyStorePassword);
        kmf.init(keyStore, keyStorePassword);
        
        return kmf.getKeyManagers();
    }
    
    /**
     * Initializes a trust manager factory with a source of provider-specific
     * trust material, and returns one trust manager for each type of trust 
     * material.
     * 
     * @return The trust managers for the truststore.
     * 
     * @throws IOException If there is an I/O or format problem with the 
     *         keystore data, if a password is required but not given, or if the 
     *         given password was incorrect. If the error is due to a wrong 
     *         password, the {@link Throwable#getCause cause} of the 
     *         {@code IOException} should be an 
     *         {@code UnrecoverableKeyException}.
     * @throws NoSuchAlgorithmException If no {@code Provider} supports a 
     *         {@code TrustManagerFactorySpi} implementation for the specified 
     *         algorithm, or if the algorithm used to check the integrity of the 
     *         keystore cannot be found.
     * @throws KeyStoreException If no {@code Provider} supports a 
     *         {@code KeyStoreSpi} implementation for the specified type, or if 
     *         the trust manager initialization operation fails.
     * @throws CertificateException If any of the certificates in the keystore 
     *         could not be loaded.
     */
    private TrustManager[] getTrustManagers() 
            throws IOException, NoSuchAlgorithmException, KeyStoreException, 
                   CertificateException {
        
        if (trustStorePath == null) {
            return new TrustManager[0];
        }
        
        var tmf = TrustManagerFactory.getInstance("SunX509");
        var trustStore = getKeyStore(trustStoreType, trustStorePath, 
                trustStorePassword);
        tmf.init(trustStore);
        
        return tmf.getTrustManagers();
    }
    
    /**
     * Loads a keystore or truststore from file with or without a password.
     * 
     * @param storeType The type of keystore with PKCS12 being the default.
     * @param storePath The path to the keystore file containing key or trust 
     *        material.
     * @param storePassword The password used to check the integrity of the 
     *        keystore, the password used to unlock the keystore, or 
     *        {@code null}.
     * @return A keystore instance of the specified type to be used as a 
     *         keystore or a truststore.
     * 
     * @throws IOException If there is an I/O or format problem with the 
     *         keystore data, if a password is required but not given, or if the 
     *         given password was incorrect. If the error is due to a wrong 
     *         password, the {@link Throwable#getCause cause} of the 
     *         {@code IOException} should be an 
     *         {@code UnrecoverableKeyException}.
     * @throws KeyStoreException If no {@code Provider} supports a 
     *         {@code KeyStoreSpi} implementation for the specified type.
     * @throws NoSuchAlgorithmException If the algorithm used to check the 
     *         integrity of the keystore cannot be found.
     * @throws CertificateException If any of the certificates in the keystore 
     *         could not be loaded.
     */
    private static KeyStore getKeyStore(KeyStoreType storeType, Path storePath, 
            char[] storePassword) 
            throws IOException, KeyStoreException, NoSuchAlgorithmException, 
                   CertificateException {

        var ks = KeyStore.getInstance(storeType.value);

        try (var inputStream = new FileInputStream(storePath.toFile())) {
            ks.load(inputStream, storePassword);
        }

        return ks;
    }
}