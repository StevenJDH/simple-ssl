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

/**
 * PEM derived SSLContext implementation. Contains all configuration information 
 * needed to build a custom context.
 * 
 * @since 1.0
 */
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
    static SSLContext create(PEMContextBuilderImpl builder) {
        return new PEMContextImpl(builder).getSSLContext();
    }
    
    /**
     * Sets the initial state collected from the builder that will be used to 
     * create a custom {@link SSLContext}.
     * 
     * @param builder The configuration needed to build a {@code SSLContext}.
     * 
     * @throws GenericKeyStoreException If no certificate or private key paths 
     *         were specified.
     */
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
            throw new GenericKeyStoreException("No certificate or private key paths were specified.");
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
     * @throws UncheckedIOException If there was an I/O problem with reading or 
     *         storing keystore related data.
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
     * material, and returns one key manager for each type of key material. The 
     * keystore can be optionally saved to the specified path defined by 
     * {@link #keyStorePath}.
     * 
     * @return The key managers for the keystore.
     * 
     * @throws IOException If an I/O error occurs when reading from the file or 
     *         a malformed or unmappable byte sequence is read, parsing the 
     *         ASN.1 encoding, an I/O or format problem with the keystore data, 
     *         a password is required but not given, or when the given password 
     *         was incorrect. If the error is due to a wrong password, the 
     *         {@link Throwable#getCause cause} of the {@code IOException} 
     *         should be an {@code UnrecoverableKeyException}.
     * @throws NoSuchAlgorithmException If no {@code Provider} supports a 
     *         {@code KeyManagerFactorySpi}, {@code KeyFactorySpi}, 
     *         {@code SecretKeyFactorySpi}, or {@code CipherSpi} implementation 
     *         for the specified algorithm, or if {@code transformation} is 
     *         {@code null}, empty, or in an invalid format, or if the algorithm 
     *         used to check the integrity of the keystore cannot be found.
     * @throws KeyStoreException If no {@code Provider} supports a
     *         {@code KeyStoreSpi} implementation for the specified type, or if 
     *         the keystore has not been initialized (loaded), the given key 
     *         cannot be protected, or this operation fails for some other 
     *         reason, or if the key manager initialization operation fails.
     * @throws CertificateException If there are parsing errors, or if any of 
     *         the certificates in the keystore could not be loaded or stored.
     * @throws UnrecoverableKeyException If the key cannot be recovered (e.g. 
     *         the given password is wrong).
     * @throws InvalidKeySpecException If the given key specification is 
     *         inappropriate for this key factory to produce a private key, or 
     *         its keysize exceeds the maximum allowable keysize (as determined 
     *         from the configured jurisdiction policy files).
     * @throws NoSuchPaddingException If {@code transformation} contains a 
     *         padding scheme that is not available.
     * @throws InvalidKeyException If the given key is inappropriate for
     *         initializing this cipher, or its keysize exceeds the maximum 
     *         allowable keysize (as determined from the configured jurisdiction 
     *         policy files).
     * @throws InvalidAlgorithmParameterException If the given algorithm
     *         parameters are inappropriate for this cipher, or this cipher 
     *         requires algorithm parameters and {@code params} is null, or the 
     *         given algorithm parameters imply a cryptographic strength that 
     *         would exceed the legal limits (as determined from the configured 
     *         jurisdiction policy files).
     */
    private KeyManager[] getKeyManagers() 
            throws IOException, NoSuchAlgorithmException, KeyStoreException, 
                   CertificateException, UnrecoverableKeyException, 
                   InvalidKeySpecException, NoSuchPaddingException, 
                   InvalidKeyException, InvalidAlgorithmParameterException {
        
        if (privateKeyPath == null) {
            return new KeyManager[0];
        }
        
        var kmf = KeyManagerFactory.getInstance("SunX509");
        var keyStore = getKeyStore(keyStoreType, privateKeyPath, 
                privateKeyPassword, keyStorePassword, 
                privateKeyCertChainPath);
        
        kmf.init(keyStore, privateKeyPassword);
        
        if (keyStorePath != null) {
            saveKeyStore(keyStore, keyStorePath, keyStorePassword);
        }
        
        return kmf.getKeyManagers();
    }
    
    /**
     * Creates a keystore from a private key and certificate pair to be used as 
     * a keystore. See {@link #getTrustStore} for truststore instances.
     * 
     * @param storeType The type of keystore with PKCS12 being the default.
     * @param keyPath The path to the file containing the private key material.
     * @param keyPassword The password used to decrypt the encrypted key. If 
     *        this is set to null or an empty char[], it will be assumed that
     *        decryption is not needed. The password is cloned before it is 
     *        stored in the new {@link PBEKeySpec} object.
     * @param storePassword The password used to generate and check the 
     *        integrity of the keystore and unlock the it.
     * @param certChain The certificate chain with the corresponding public key 
     *        that pairs with the private key.
     * @return A keystore instance of the specified type.
     * 
     * @throws IOException If an I/O error occurs when reading from the file or 
     *         a malformed or unmappable byte sequence is read, parsing the 
     *         ASN.1 encoding, an I/O or format problem with the keystore data, 
     *         a password is required but not given, or when the given password 
     *         was incorrect. If the error is due to a wrong password, the 
     *         {@link Throwable#getCause cause} of the {@code IOException} 
     *         should be an {@code UnrecoverableKeyException}.
     * @throws KeyStoreException If no {@code Provider} supports a
     *         {@code KeyStoreSpi} implementation for the specified type, or if 
     *         the keystore has not been initialized (loaded), the given key 
     *         cannot be protected, or this operation fails for some other 
     *         reason.
     * @throws NoSuchAlgorithmException If no {@code Provider} supports a 
     *         {@code KeyFactorySpi}, {@code SecretKeyFactorySpi}, or 
     *         {@code CipherSpi} implementation for the specified algorithm, or 
     *         if {@code transformation} is {@code null}, empty, or in an 
     *         invalid format, or if the algorithm used to check the integrity 
     *         of the keystore cannot be found.
     * @throws CertificateException If there are parsing errors, or if any of 
     *         the certificates in the keystore could not be loaded.
     * @throws InvalidKeySpecException If the given key specification is 
     *         inappropriate for this key factory to produce a private key, or 
     *         its keysize exceeds the maximum allowable keysize (as determined 
     *         from the configured jurisdiction policy files).
     * @throws NoSuchPaddingException If {@code transformation} contains a 
     *         padding scheme that is not available.
     * @throws InvalidKeyException If the given key is inappropriate for
     *         initializing this cipher, or its keysize exceeds the maximum 
     *         allowable keysize (as determined from the configured jurisdiction 
     *         policy files).
     * @throws InvalidAlgorithmParameterException If the given algorithm
     *         parameters are inappropriate for this cipher, or this cipher 
     *         requires algorithm parameters and {@code params} is null, or the 
     *         given algorithm parameters imply a cryptographic strength that 
     *         would exceed the legal limits (as determined from the configured 
     *         jurisdiction policy files).
     */
    private static KeyStore getKeyStore(KeyStoreType storeType, Path keyPath, 
            char[] keyPassword, char[] storePassword, Path certChain) 
            throws IOException, KeyStoreException, NoSuchAlgorithmException, 
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
    
    /**
     * Loads a private key object from the provided key specification
     * (key material).
     * 
     * @param keyPath The path to the private key material.
     * @param keyPassword The password used to decrypt the encrypted key. If 
     *        this is set to null or an empty char[], it will be assumed that
     *        decryption is not needed. The password is cloned before it is 
     *        stored in the new {@link PBEKeySpec} object.
     * @return An RSA private key.
     * 
     * @throws IOException If an I/O error occurs reading from the file or a 
     *         malformed or unmappable byte sequence is read, or if an error 
     *         occurs when parsing the ASN.1 encoding.
     * @throws NoSuchAlgorithmException If no {@code Provider} supports a 
     *         {@code KeyFactorySpi}, {@code SecretKeyFactorySpi}, or 
     *         {@code CipherSpi} implementation for the specified algorithm, or 
     *         if {@code transformation} is {@code null}, empty, or in an 
     *         invalid format.
     * @throws InvalidKeySpecException If the given key specification is 
     *         inappropriate for this key factory to produce a private key, or 
     *         its keysize exceeds the maximum allowable keysize (as determined 
     *         from the configured jurisdiction policy files).
     * @throws NoSuchPaddingException If {@code transformation} contains a 
     *         padding scheme that is not available.
     * @throws InvalidKeyException If the given key is inappropriate for
     *         initializing this cipher, or its keysize exceeds the maximum 
     *         allowable keysize (as determined from the configured jurisdiction 
     *         policy files).
     * @throws InvalidAlgorithmParameterException If the given algorithm
     *         parameters are inappropriate for this cipher, or this cipher 
     *         requires algorithm parameters and {@code params} is null, or the 
     *         given algorithm parameters imply a cryptographic strength that 
     *         would exceed the legal limits (as determined from the configured 
     *         jurisdiction policy files).
     */
    private static RSAPrivateKey loadPrivateKey(Path keyPath, char[] keyPassword) 
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, 
                   NoSuchPaddingException, InvalidKeyException, 
                   InvalidAlgorithmParameterException {
        
        var derKey = CertUtil.toDERPrivateKey(Files.readString(keyPath));
        var keyFactoryRSA = KeyFactory.getInstance("RSA");
        var keySpec = getKeySpec(derKey, keyPassword);
        
        return (RSAPrivateKey) keyFactoryRSA.generatePrivate(keySpec);
    }
    
    /**
     * Extracts the enclosed {@link PKCS8EncodedKeySpec} object from the 
     * encrypted key data and returns it.
     * 
     * <p><b>Note:</b> In order to successfully retrieve the enclosed
     * PKCS8EncodedKeySpec object, the {@link Cipher} needs to be initialized 
     * to either {@code Cipher.DECRYPT_MODE} or {@code Cipher.UNWRAP_MODE}, with 
     * the same key and parameters used for generating the encrypted data.
     * 
     * @param derKey The key, which is assumed to be encoded according to the 
     *        PKCS #8 standard. The contents of the array are copied to protect 
     *        against subsequent modification.
     * @param keyPassword The password used to decrypt the encrypted key. If 
     *        this is set to null or an empty char[], it will be assumed that
     *        decryption is not needed. The password is cloned before it is 
     *        stored in the new {@link PBEKeySpec} object.
     * @return The PKCS8EncodedKeySpec object.
     * 
     * @throws IOException If an error occurs when parsing the ASN.1 encoding.
     * @throws NoSuchAlgorithmException If no {@code Provider} supports a 
     *         {@code SecretKeyFactorySpi} or {@code CipherSpi} implementation 
     *         for the specified algorithm, or if {@code transformation} is 
     *         {@code null}, empty, or in an invalid format.
     * @throws NoSuchPaddingException If {@code transformation} contains a 
     *         padding scheme that is not available.
     * @throws InvalidKeySpecException If the given key specification
     *         is inappropriate for this secret-key factory to produce a secret 
     *         key, or if the given cipher is inappropriate for the encrypted 
     *         data, or the encrypted data is corrupted and cannot be decrypted.
     * @throws InvalidKeyException If the given key is inappropriate for
     *         initializing this cipher, or its keysize exceeds the maximum 
     *         allowable keysize (as determined from the configured jurisdiction 
     *         policy files).
     * @throws InvalidAlgorithmParameterException If the given algorithm
     *         parameters are inappropriate for this cipher, or this cipher 
     *         requires algorithm parameters and {@code params} is null, or the 
     *         given algorithm parameters imply a cryptographic strength that 
     *         would exceed the legal limits (as determined from the configured 
     *         jurisdiction policy files).
     */
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
    
    /**
     * Initializes a trust manager factory with a source of provider-specific
     * trust material, and returns one trust manager for each type of trust 
     * material. The truststore can be optionally saved to the specified path 
     * defined by {@link #trustStorePath}.
     * 
     * @return The trust managers for the truststore.
     * 
     * @throws IOException If there are IO related errors.
     * @throws NoSuchAlgorithmException If no {@code Provider} supports a 
     *         {@code MessageDigestSpi} implementation for the specified 
     *         algorithm, or if the appropriate data integrity algorithm could 
     *         not be found.
     * @throws KeyStoreException If no {@code Provider} supports a 
     *         {@code KeyStoreSpi} implementation for the specified type, or if 
     *         the trust manager initialization operation fails.
     * @throws CertificateException If there are parsing errors.
     */
    private TrustManager[] getTrustManagers() 
            throws IOException, NoSuchAlgorithmException, KeyStoreException, 
                   CertificateException {
        
        if (publicKeyPath == null) {
            return new TrustManager[0];
        }
        
        var tmf = TrustManagerFactory.getInstance("SunX509");
        var trustStore = getTrustStore(trustStoreType, publicKeyPath);
        tmf.init(trustStore);
        
        if (trustStorePath != null) {
            saveKeyStore(trustStore, trustStorePath, trustStorePassword);
        }
        
        return tmf.getTrustManagers();
    }
    
    /**
     * Creates a keystore from a certificate or certificate chain to be used as 
     * a truststore. See {@link #getKeyStore} for keystore instances.
     * 
     * <p><b>Note:</b> The alias of a certificate in the truststore will be the 
     * first 39 characters of its SHA-1 thumbprint.
     * 
     * @param storeType The type of keystore with PKCS12 being the default.
     * @param certPath The path to the file containing one or more certificates.
     * @return A keystore instance of the specified type.
     * 
     * @throws KeyStoreException If no {@code Provider} supports a
     *         {@code KeyStoreSpi} implementation for the specified type.
     * @throws IOException If there are IO related errors.
     * @throws NoSuchAlgorithmException If the algorithm used to check the 
     *         integrity of the keystore cannot be found, or if no 
     *         {@code Provider} supports a {@code MessageDigestSpi} 
     *         implementation for the specified algorithm.
     * @throws CertificateException If there are parsing errors.
     */
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
    
    /**
     * Loads a file containing a certificate or certificate chain that is Base64 
     * encoded.
     * 
     * @param certPath The path to the file containing one or more certificates.
     * @return A (possibly empty) list of {@link X509Certificate} objects 
     * initialized with the data from the provided path.
     * 
     * @throws IOException If there are IO related errors.
     * @throws CertificateException If there are parsing errors.
     */
    private static List<X509Certificate> loadPublicKeyChain(Path certPath) 
            throws IOException, CertificateException {
        
        var certificateFactoryX509 = CertificateFactory.getInstance("X.509");
        try (var is = new FileInputStream(certPath.toFile())) {
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