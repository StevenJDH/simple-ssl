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

import io.github.stevenjdh.simple.git.BuildInfo;
import io.github.stevenjdh.simple.git.GitProperties;
import javax.net.ssl.SSLContext;
import java.nio.file.Path;

/**
 * A Simple SSLContext.
 * 
 * <p>A {@code SimpleSSLContext} can be used to build a custom SSLContext for 
 * secure communication using an optional set of keystore and truststore 
 * instances.
 * 
 * @since 1.0
 */
public interface SimpleSSLContext {

    /**
     * The supported keystore formats.
     */
    public enum KeyStoreType {
        
        /**
         * PKCS#12 format.
         */
        PKCS12("PKCS12"),
        
        /**
         * JKS format.
         */
        JKS("JKS");
        
        /**
         * String friendly representation of the keystore formats.
         */
        public final String value;
        KeyStoreType(String type) { value = type; }
        
        @Override
        public String toString() {
            return value;
        }
    }
    
    /**
     * Creates a new {@link SSLContext} instance with a default context similar 
     * to {@link SSLContext#getDefault()}.
     * 
     * <p><b>Note:</b> The {@code SSLContext} will use TLS v1.3 by default.
     * 
     * @return A new {@code SSLContext}.
     */
    public static SSLContext newSSLContext() {
        return newBuilder().build();
    }
    
    /**
     * Creates a new {@link SimpleSSLContext} builder to configure a custom 
     * {@link SSLContext} instance using an optional set of keystore and 
     * truststore instances.
     * 
     * @return A {@code SimpleSSLContext.Builder}.
     */
    public static Builder newBuilder() {
        return new SSLContextBuilderImpl();
    }
    
    /**
     * A builder of {@linkplain SimpleSSLContext SSLContext instances}.
     * 
     * <p>Builders are created by invoking {@link SimpleSSLContext#newBuilder()
     * newBuilder}. Each of the setter methods modifies the state of the builder
     * and returns the same instance. Builders are not thread-safe and should 
     * not be used concurrently from multiple threads without external 
     * synchronization.
     * 
     * @since 1.0
     */
    public interface Builder {
        
        /**
         * Optionally sets the keystore configuration to be used when building 
         * an {@link SSLContext}.
         * 
         * @param keyMaterialPath The path to the keystore file containing key 
         *        material.
         * @param password The password used to unlock the keystore. If this is 
         *        set to null or an empty char[], it will be assumed that a 
         *        password is not needed.
         * @return This builder.
         */
        Builder withKeyStore(Path keyMaterialPath, char[] password);
        
        /**
         * Optionally sets the truststore configuration to be used when building 
         * an {@link SSLContext}.
         * 
         * @param trustMaterialPath The path to the truststore file containing 
         *        trust material.
         * @param password The password used to unlock the truststore. If this is 
         *        set to null or an empty char[], it will be assumed that a 
         *        password is not needed.
         * @return This builder.
         */
        Builder withTrustStore(Path trustMaterialPath, char[] password);
        
        /**
         * Optionally sets the keystore type with PKCS12 being the default.
         * 
         * @param type The keystore type such as PKCS12 or the legacy JKS.
         * @return This builder.
         */
        Builder keyStoreType(KeyStoreType type);
        
        /**
         * Optionally sets the truststore type with PKCS12 being the default.
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
    
    /**
     * Create new {@link PEMContext} builder to configure a custom 
     * {@link SSLContext} instance using PEM files.
     * 
     * @return A {@code PEMContext.Builder}.
     */
    public static PEMContext.Builder newPEMContextBuilder() {
        return new PEMContextBuilderImpl();
    }
    
    /**
     * Gets build information from when the library was created.
     * 
     * @return Build information around specific git commit.
     */
    public static GitProperties getBuildInfo() {
        return new BuildInfo().getGitProperties();
    }
}