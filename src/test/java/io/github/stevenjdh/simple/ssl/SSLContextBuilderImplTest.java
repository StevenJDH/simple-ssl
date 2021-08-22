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

import io.github.stevenjdh.support.BaseTestSupport;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;

class SSLContextBuilderImplTest extends BaseTestSupport {
    
    @Test
    @DisplayName("Should return SSL context using TLS v1.3 for every instance created.")
    void Should_ReturnSSLContextUsingTLS13_ForEveryInstanceCreated() {
        var builder = new SSLContextBuilderImpl();
        
        builder.trustStorePath = BADSSL_TRUSTSTORE_PKCS12.toPath();
        builder.trustStorePassword = "test".toCharArray();
        
        var ctx = SimpleSSLContextImpl.create(builder);
        
        assertNotNull(ctx);
        assertEquals("TLSv1.3", ctx.getProtocol());
    }
}