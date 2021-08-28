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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;

final class PEMContextImpl implements PEMContext {

    private final Path publicKeyPath;
    private final Path privateKeyPath;
    private final char[] privateKeyPassword;
    private final Path privateKeyCertChainPath;
    private final Path keyStorePath;
    private final char[] keyStorePassword;
    private final Path trustStorePath;
    private final char[] trustStorePassword;
    private final KeyStoreType keyStoreType;
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
        privateKeyCertChainPath = builder.privateKeyCertChainPath;
        keyStorePath = builder.keyStorePath;
        keyStorePassword = builder.keyStorePassword;
        trustStorePath = builder.trustStorePath;
        trustStorePassword = builder.trustStorePassword;
        keyStoreType = builder.keyStoreType;
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
            var keyManagers = getKeyManagers(keyStoreType, privateKeyPath, 
                 privateKeyPassword, keyStorePath, keyStorePassword, 
                 privateKeyCertChainPath);
            
            var trustManagers = getTrustManagers(trustStoreType, publicKeyPath, 
                    trustStorePath, trustStorePassword);
            
            var context = SSLContext.getInstance("TLSv1.3");
            context.init(keyManagers, trustManagers, new SecureRandom());

            return context;
        } catch (GeneralSecurityException ex) {
            throw new GenericKeyStoreException(ex.getMessage(), ex);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex.getMessage(), ex);
        }
    }

    private static KeyManager[] getKeyManagers(KeyStoreType storeType, Path keyPath, 
            char[] keyPassword, Path storePath, char[] storePassword, Path certChain) 
            throws NoSuchAlgorithmException, KeyStoreException, IOException, 
                   CertificateException, UnrecoverableKeyException, 
                   InvalidKeySpecException, NoSuchPaddingException, 
                   InvalidKeyException, InvalidAlgorithmParameterException {
        
        if (keyPath == null) {
            return new KeyManager[0];
        }
        
        var kmf = KeyManagerFactory.getInstance("SunX509");
        var keyStore = getKeyStore(storeType, keyPath, keyPassword, storePassword, certChain);
        kmf.init(keyStore, keyPassword);
        
        if (storePath != null) {
            saveKeyStore(keyStore, storePath, storePassword);
        }
        
        return kmf.getKeyManagers();
    }
    
    private static KeyStore getKeyStore(KeyStoreType storeType, Path keyPath, 
            char[] keyPassword, char[] storePassword, Path certChain) 
            throws KeyStoreException, IOException, NoSuchAlgorithmException, 
                   CertificateException, InvalidKeySpecException, 
                   NoSuchPaddingException, InvalidKeyException, 
                   InvalidAlgorithmParameterException {
        
        var ks = KeyStore.getInstance(storeType.value);
        RSAPrivateKey privateKey = loadPrivateKey(keyPath, keyPassword);
        var chain = loadPublicKeyChain(certChain);
        ks.load(null, storePassword);
        ks.setKeyEntry("signing-key-alias", privateKey, keyPassword,
                chain.toArray(new X509Certificate[chain.size()]));
       
        return ks;
    }
    
    private static RSAPrivateKey loadPrivateKey(Path keyPath, char[] keyPassword) 
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, 
                   NoSuchPaddingException, InvalidKeyException, 
                   InvalidAlgorithmParameterException {
        
        var derKey = CertUtil.toDERPrivateKey(Files.readString(keyPath));
        var keyFactoryRSA = KeyFactory.getInstance("RSA");
        var keySpec = getKeySpec(derKey, keyPassword);
        
        return (RSAPrivateKey) keyFactoryRSA.generatePrivate(keySpec);
    }
    
    private static PKCS8EncodedKeySpec getKeySpec(byte[] derKey, char[] keyPassword)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidKeySpecException, InvalidKeyException, 
                   InvalidAlgorithmParameterException {

        if (keyPassword == null || keyPassword.length == 0) {
            return new PKCS8EncodedKeySpec(derKey);
        }

        var encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(derKey);
        var keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
        var pbeKeySpec = new PBEKeySpec(keyPassword);
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        var cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, encryptedPrivateKeyInfo.getAlgParameters());

        return encryptedPrivateKeyInfo.getKeySpec(cipher);
    }
    
    private static TrustManager[] getTrustManagers(KeyStoreType storeType, Path certPath, 
            Path storePath, char[] storePassword) 
            throws NoSuchAlgorithmException, KeyStoreException, IOException, 
                   CertificateException {
        
        if (certPath == null) {
            return new TrustManager[0];
        }
        
        var tmf = TrustManagerFactory.getInstance("SunX509");
        var trustStore = getTrustStore(storeType, certPath);
        tmf.init(trustStore);
        
        if (storePath != null) {
            saveKeyStore(trustStore, storePath, storePassword);
        }
        
        return tmf.getTrustManagers();
    }
    
    private static KeyStore getTrustStore(KeyStoreType storeType, Path certPath)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, 
                   CertificateException {
        
        var ks = KeyStore.getInstance(storeType.value);
        var chain = loadPublicKeyChain(certPath);
        
        LOG.log(Level.INFO, "Certificate chain size: {0}", chain.size());
        ks.load(null);
        
        for (var cert : chain) {
            // Alias length is limited to 39 characters, and the rest is left off.
            String alias = CertUtil.getThumbprint(cert, "", HashType.SHA_1);
            ks.setCertificateEntry(alias.toLowerCase(), cert);
        }
        
        return ks;
    }
    
    private static List<X509Certificate> loadPublicKeyChain(Path keyPath) 
            throws IOException, CertificateException {
        
        var certificateFactoryX509 = CertificateFactory.getInstance("X.509");
        try (var is = new FileInputStream(keyPath.toFile())) {
            return certificateFactoryX509.generateCertificates(is).stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .toList(); // Returns type-safe immutable list.
        }
    }
    
    /**
     * Stores a keystore to the provided path, and protects its integrity with a 
     * password.
     * 
     * @param ks The {@link KeyStore} instance to save.
     * @param savePath The path used for saving the keystore.
     * @param password The password to generate the keystore integrity check.
     * 
     * @throws IOException If there was an I/O problem with storing the data.
     * @throws KeyStoreException If the keystore has not been initialized (loaded).
     * @throws NoSuchAlgorithmException If the appropriate data integrity algorithm 
     *         could not be found.
     * @throws CertificateException If any of the certificates included in the 
     *         keystore data could not be stored.
     * @throws GenericKeyStoreException If minimum password length of 4 is not met.
     */
    private static void saveKeyStore(KeyStore ks, Path savePath, char[] password) 
            throws IOException, KeyStoreException, NoSuchAlgorithmException, 
                   CertificateException {
        
        if (password == null || password.length < 4) {
            throw new GenericKeyStoreException("KeyStore password must contain at least 4 characters.");
        }
        
        try (var fos = new FileOutputStream(savePath.toFile())) {
            ks.store(fos, password);
        }
    }
}