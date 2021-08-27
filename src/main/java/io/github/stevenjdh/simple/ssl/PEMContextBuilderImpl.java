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

import java.nio.file.Path;
import javax.net.ssl.SSLContext;
import io.github.stevenjdh.simple.ssl.SimpleSSLContext.KeyStoreType;

class PEMContextBuilderImpl implements PEMContext.Builder {

    Path publicKeyPath;
    Path privateKeyPath;
    char[] privateKeyPassword = new char[0]; // Needed for setKeyEntry method when JKS.
    Path privateKeyCertChainPath;
    Path keyStorePath;
    char[] keyStorePassword;
    Path trustStorePath;
    char[] trustStorePassword;
    KeyStoreType keyStoreType = KeyStoreType.PKCS12;
    KeyStoreType trustStoreType = KeyStoreType.PKCS12;
    
    @Override
    public PEMContext.Builder withPublicKey(Path keyPath) {
        publicKeyPath = keyPath;
        return this;
    }

    @Override
    public PEMContext.Builder withPrivateKey(Path keyPath, Path certPath) {
        privateKeyPath = keyPath;
        privateKeyCertChainPath = certPath;
        return this;
    }
    
    @Override
    public PEMContext.Builder withPrivateKeyPassword(char[] password) {
        privateKeyPassword = password;
        return this;
    }

    @Override
    public PEMContext.Builder saveKeyStore(Path keyMaterialPath, char[] password) {
        keyStorePath = keyMaterialPath;
        keyStorePassword = password;
        return this;
    }
    
    @Override
    public PEMContext.Builder saveTrustStore(Path trustMaterialPath, char[] password) {
        trustStorePath = trustMaterialPath;
        trustStorePassword = password;
        return this;
    }
    
    @Override
    public PEMContext.Builder keyStoreType(KeyStoreType type) {
        keyStoreType = type;
        return this;
    }

    @Override
    public PEMContext.Builder trustStoreType(KeyStoreType type) {
        trustStoreType = type;
        return this;
    }
    
    @Override
    public SSLContext build() {
        return PEMContextImpl.create(this);
    }
}