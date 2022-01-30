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

import java.nio.file.Path;
import javax.net.ssl.SSLContext;
import io.github.stevenjdh.simple.ssl.SimpleSSLContext.KeyStoreType;

/**
 * A PEM derived SSLContext.
 * 
 * <p>A {@code PEMContext} can be used to build a custom SSLContext for 
 * secure communication using an optional set of keystore and truststore 
 * instances that are derived from Base64 encoded public and private keys.
 * 
 * @since 1.0
 */
interface PEMContext {
    
    /**
     * A builder of {@linkplain PEMContext PEM derived SSLContext instances}.
     * 
     * <p>PEM derived {@code SSLContext} instances are created through the
     * {@link PEMContext.Builder}. Each of the setter methods modifies the state 
     * of the builder and returns the same instance. Builders are not 
     * thread-safe and should not be used concurrently from multiple threads 
     * without external synchronization.
     * 
     * @since 1.0
     */
    interface Builder {
        
        /**
         * Optionally sets the truststore configuration using a Base64 encoded 
         * certificate or certificate chain for building an {@link SSLContext}.
         * 
         * @param certPath The path to the file containing one or more 
         *        certificates.
         * @return This builder.
         */
        Builder withPublicKey(Path certPath);
        
        /**
         * Optionally sets the keystore configuration using a Base64 encoded 
         * private key for building an {@link SSLContext}.
         * 
         * @param keyPath The path to the file containing the private key 
         *        material.
         * @param certPath The path to the file containing the certificate or 
         *        certificate chain with the corresponding public key that pairs 
         *        with the private key.
         * @return This builder.
         */
        Builder withPrivateKey(Path keyPath, Path certPath);
        
        /**
         * Optionally sets the password for the encrypted private key material.
         * 
         * @param password The password used to decrypt the encrypted key. If 
         *        this is set to null or an empty char[], it will be assumed 
         *        that decryption is not needed.
         * @return This builder.
         */
        Builder withPrivateKeyPassword(char[] password);
        
        /**
         * Optionally saves the built keystore to the provided path, and 
         * protects its integrity with a password.
         * 
         * @param keyMaterialPath The path used for saving the keystore.
         * @param password The password to set when saving the keystore, which 
         *        has a minimum length of 4 characters.
         * @return This builder.
         */
        Builder saveKeyStore(Path keyMaterialPath, char[] password);
        
        /**
         * Optionally saves the built truststore to the provided path, and 
         * protects its integrity with a password.
         * 
         * @param trustMaterialPath The path used for saving the truststore.
         * @param password The password to set when saving the truststore, which 
         *        has a minimum length of 4 characters.
         * @return This builder.
         */
        Builder saveTrustStore(Path trustMaterialPath, char[] password);
        
        /**
         * Optionally sets the keystore type being built with PKCS12 being the 
         * default.
         * 
         * @param type The keystore type such as PKCS12 or the legacy JKS.
         * @return This builder.
         */
        Builder keyStoreType(KeyStoreType type);
        
        /**
         * Optionally sets the truststore type being built with PKCS12 being the 
         * default.
         * 
         * @param type The truststore type such as PKCS12 or the legacy JKS.
         * @return This builder.
         */
        Builder trustStoreType(KeyStoreType type);
        
        /**
         * Returns a new {@link SSLContext} instance built from the current 
         * state of this builder.
         * 
         * @return A new {@code SSLContext}.
         */
        SSLContext build();
    }
}