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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import io.github.stevenjdh.simple.exceptions.GenericKeyStoreException;
import io.github.stevenjdh.simple.ssl.SimpleSSLContext.KeyStoreType;
import io.github.stevenjdh.simple.security.cert.CertUtil;
import io.github.stevenjdh.simple.security.cert.CertUtil.HashType;

final class PEMContextImpl implements PEMContext {

    private final Path publicKeyPath;
    private final Path privateKeyPath;
    private final char[] privateKeyPassword;
    private final Path trustStorePath;
    private final char[] trustStorePassword;
    private final KeyStoreType trustStoreType;
    private final SSLContext sslContext;
    private static final Logger LOG = Logger.getLogger(PEMContextImpl.class.getName());
    
    static SSLContext create(PEMContextBuilderImpl builder) {
        return new PEMContextImpl(builder).getSSLContext();
    }
    
    private PEMContextImpl(PEMContextBuilderImpl builder) {
        publicKeyPath = builder.publicKeyPath;
        privateKeyPath = builder.privateKeyPath;
        privateKeyPassword = builder.privateKeyPassword;
        trustStorePath = builder.trustStorePath;
        trustStorePassword = builder.trustStorePassword;
        trustStoreType = builder.trustStoreType;
        
        if (builder.publicKeyPath == null && builder.privateKeyPath == null) {
            throw new GenericKeyStoreException("No certificate paths were specified.");
        } else {
            sslContext = createSSLContext();
        }
    }

    SSLContext getSSLContext() {
        return sslContext;
    }
    
    private SSLContext createSSLContext() {
        try {
            //var kmf = KeyManagerFactory.getInstance("SunX509");
            var tmf = TrustManagerFactory.getInstance("SunX509");
            //var keyStore = getKeyStore(clientCertPath, clientCertPassword, false);
            var trustStore = getKeyStore(trustStoreType, publicKeyPath);
            var context = SSLContext.getInstance("TLSv1.3");

            //kmf.init(keyStore, clientCertPassword);
            tmf.init(trustStore);
            context.init(null, tmf.getTrustManagers(), new SecureRandom());

            if (trustStorePath != null) {
                saveTrustStore(trustStore, trustStorePath, trustStorePassword);
            }

            return context;
        } catch (GeneralSecurityException ex) {
            throw new GenericKeyStoreException(ex.getMessage(), ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex.getMessage(), ex);
        }
    }

    private static KeyStore getKeyStore(KeyStoreType storeType, Path keyPath)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, 
            CertificateException {

        // TODO: Add private key logic and tests.
        var ks = KeyStore.getInstance(storeType.value);
        var chain = loadPublicKeyChain(keyPath);
        
        LOG.log(Level.INFO, "Certificate chain size: {0}", chain.size());
        ks.load(null, null);
        
        for (var cert : chain) {
            // Alias length is limited to 39 characters, and the rest is left off.
            String alias = CertUtil.getThumbprint(cert, "", HashType.SHA_1);
            ks.setCertificateEntry(alias.toLowerCase(), cert);
        }
        
        return ks;
    }
    
    private static RSAPrivateKey loadPrivateKey(Path keyPath) throws IOException, 
            NoSuchAlgorithmException, InvalidKeySpecException {
        var derData = CertUtil.toDERPrivateKey(Files.readString(keyPath));
        var keyFactoryRSA = KeyFactory.getInstance("RSA");
        var keySpec = new PKCS8EncodedKeySpec(derData); // TODO: setKeyEntry says if JKS, encode as EncryptedPrivateKeyInfo.
        
        return (RSAPrivateKey) keyFactoryRSA.generatePrivate(keySpec); // TODO: handle chain maybe with setKeyEntry.
    }

    private static List<X509Certificate> loadPublicKeyChain(Path keyPath) throws IOException, 
            CertificateException {
        var certificateFactoryX509 = CertificateFactory.getInstance("X.509");
        try (var is = new FileInputStream(keyPath.toFile())) {
            return certificateFactoryX509.generateCertificates(is).stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .toList(); // Returns type-safe immutable list.
        }
    }
    
    private static void saveTrustStore(KeyStore ks, Path savePath, char[] password) throws IOException, 
            KeyStoreException, NoSuchAlgorithmException, CertificateException {
        try (var os = new FileOutputStream(savePath.toFile())) {
            ks.store(os, password); // TODO: must have a password or it won't contain certs.
        }
    }
}