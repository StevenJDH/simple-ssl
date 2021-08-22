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

import io.github.stevenjdh.simple.git.BuildInfo;
import io.github.stevenjdh.simple.git.GitProperties;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.file.Path;

public abstract class SimpleSSLContext {

    public enum KeyStoreType {
        PKCS12("PKCS12"),
        JKS("JKS");
        
        public final String value;
        KeyStoreType(String type) { value = type; }
        
        @Override
        public String toString() {
            return value;
        }
    }
    
    protected SimpleSSLContext() {}
    
    public static SSLContext newSSLContext() {
        return newBuilder().build();
    }
    
    public static Builder newBuilder() {
        return new SSLContextBuilderImpl();
    }
    
    public interface Builder {
        Builder withKeyStore(Path keyMaterialPath, char[] password);
        
        Builder withTrustStore(Path trustMaterialPath, char[] password);
              
        Builder keyStoreType(KeyStoreType type);
        
        Builder trustStoreType(KeyStoreType type);
        
        SSLContext build();
    }
    
    public static PEMContext.Builder newPEMContextBuilder() {
        return new PEMContextBuilderImpl();
    }
    
    public static GitProperties getBuildInfo() throws IOException {
        return new BuildInfo().getGitProperties();
    }
}