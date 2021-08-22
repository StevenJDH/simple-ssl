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

import javax.net.ssl.SSLContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import io.github.stevenjdh.simple.exceptions.GenericKeyStoreException;
import io.github.stevenjdh.simple.ssl.SimpleSSLContext.KeyStoreType;

import java.io.FileReader;
import java.nio.charset.StandardCharsets;

class SimpleSSLContextTest {
    
    @Test
    @DisplayName("Should return needed string representation for keystore types.")
    void Should_ReturnNeededStringRepresentation_ForKeyStoreTypes() {
        var pkcs12 = KeyStoreType.PKCS12;
        var jks = KeyStoreType.JKS;
        
        assertEquals("PKCS12", pkcs12.value);
        assertEquals("PKCS12", pkcs12.toString());
        assertEquals("JKS", jks.value);
        assertEquals("JKS", jks.toString());
    }
    
    @Test
    @DisplayName("Should return default SSL context when not building SSL context.")
    void Should_ReturnDefaultSSLContext_When_NotBuildingSSLContext() {
        var ctx = SimpleSSLContext.newSSLContext();
        
        assertNotNull(ctx);
        assertThat(ctx).isInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should return default SSL context when building directly.")
    void Should_ReturnDefaultSSLContext_When_BuildingDirectly() {
        var ctx = SimpleSSLContext.newBuilder().build();
        
        assertNotNull(ctx);
        assertThat(ctx).isInstanceOf(SSLContext.class);
    }
    
    @Test
    @DisplayName("Should throw GenericKeyStoreException when building PEM context directly.")
    void Should_ThrowGenericKeyStoreException_When_BuildingPEMContextDirectly() {
        assertThatThrownBy(() -> SimpleSSLContext.newPEMContextBuilder().build())
                .isExactlyInstanceOf(GenericKeyStoreException.class)
                .hasMessage("No certificate paths were specified.")
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("Should return build info when git.properties is present.")
    void Should_ReturnBuildInfo_When_GitPropertiesIsPresent() throws Exception {
        var pom = new MavenXpp3Reader();
        Model model;

        try (var fr = new FileReader("pom.xml", StandardCharsets.UTF_8)) {
            model = pom.read(fr);
        }

        assertThat(getClass().getClassLoader().getResource("git.properties")).isNotNull();
        assertEquals(model.getVersion(), SimpleSSLContext.getBuildInfo().getGitBuildVersion());
    }
}