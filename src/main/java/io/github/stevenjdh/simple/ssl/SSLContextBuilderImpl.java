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

import javax.net.ssl.SSLContext;
import io.github.stevenjdh.simple.ssl.SimpleSSLContext.Builder;
import io.github.stevenjdh.simple.ssl.SimpleSSLContext.KeyStoreType;
import java.nio.file.Path;

class SSLContextBuilderImpl implements SimpleSSLContext.Builder {

    Path keyStorePath;
    char[] keyStorePassword;
    Path trustStorePath;
    char[] trustStorePassword;
    KeyStoreType keyStoreType = KeyStoreType.PKCS12;
    KeyStoreType trustStoreType = KeyStoreType.PKCS12;
    
    @Override
    public Builder withKeyStore(Path keyMaterialPath, char[] password) {
        keyStorePath = keyMaterialPath;
        keyStorePassword = password;
        return this;
    }

    @Override
    public Builder withTrustStore(Path trustMaterialPath, char[] password) {
        trustStorePath = trustMaterialPath;
        trustStorePassword = password;
        return this;
    }
    
    @Override
    public Builder keyStoreType(KeyStoreType type) {
        keyStoreType = type;
        return this;
    }

    @Override
    public Builder trustStoreType(KeyStoreType type) {
        trustStoreType = type;
        return this;
    }
    
    @Override
    public SSLContext build() {
        return SimpleSSLContextImpl.create(this);
    }
}