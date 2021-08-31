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

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.github.stevenjdh.support.WireMockTestSupport;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLHandshakeException;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import wiremock.org.apache.http.HttpHeaders;

class SimpleSSLContextIT extends WireMockTestSupport {

    private static final Logger LOG = getFormattedLogger(SimpleSSLContextIT.class.getName());
    private static HttpRequest request;
    
    @BeforeAll
    static void setUp() {
        request = HttpRequest.newBuilder()
                .uri(URI.create("https://localhost:8443/test"))
                .header(HttpHeaders.ACCEPT, MEDIATYPE_TEXT_PLAIN)
                .build();
    }
    
    @AfterEach
    void afterEach() {
        stop();
    }
    
    @Test
    @DisplayName("Should pass sanity check for WireMock server.")
    void Should_PassSanityCheck_ForWireMockServer() throws Exception {
        startNewServer(new WireMockConfiguration()
            .port(8080)
        );
        
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest simpleRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/test"))
                .header(HttpHeaders.ACCEPT, MEDIATYPE_TEXT_PLAIN)
                .build();

        HttpResponse<String> response
                = client.send(simpleRequest, HttpResponse.BodyHandlers.ofString());

        LOG.log(Level.INFO, "Response: {0}", response.body());
        assertEquals("Hello World!", response.body());
    }
    
    @Test
    @DisplayName("Should throw SSLHandshakeException when client does not trust CA.")
    void Should_ThrowSSLHandshakeException_When_ClientDoesNotTrustCA() {
        startNewServer(new WireMockConfiguration()
            .port(8080)
            .httpsPort(8443)
            .keystorePath(WIREMOCK_KEYSTORE.getPath())
            .keystorePassword("test")
            .keystoreType("PKCS12")
            .keyManagerPassword("test")
        );
        
        HttpClient client = HttpClient.newHttpClient();
        
        SSLHandshakeException ex = catchThrowableOfType(() -> { 
            client.send(request, HttpResponse.BodyHandlers.ofString()); 
        }, SSLHandshakeException.class);
        
        assertThat(ex).isExactlyInstanceOf(SSLHandshakeException.class)
                .hasMessageContaining("unable to find valid certification path to requested target");
    }
    
    @Test
    @DisplayName("Should return valid response when client trusts CA.")
    void Should_ReturnValidResponse_When_ClientTrustsCA() throws Exception {
        startNewServer(new WireMockConfiguration()
            .port(8080)
            .httpsPort(8443)
            .keystorePath(WIREMOCK_KEYSTORE.getPath())
            .keystorePassword("test")
            .keystoreType("PKCS12")
            .keyManagerPassword("test")
        );
        
        var ctx = SimpleSSLContext.newBuilder()
                .withTrustStore(CLIENT_TRUSTSTORE.toPath(), "test123456".toCharArray())
                .build();
        
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .sslContext(ctx)
                .build();

        HttpResponse<String> response
                = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals("Hello World!", response.body());
    }
    
    @Test
    @DisplayName("Should throw IOException when client fails to authenticate itself.")
    void Should_ThrowIOException_When_ClientFailsToAuthenticateItself() {
        startNewServer(new WireMockConfiguration()
            .port(8080)
            .httpsPort(8443)
            .keystorePath(WIREMOCK_KEYSTORE.getPath())
            .keystorePassword("test")
            .keystoreType("PKCS12")
            .keyManagerPassword("test")
            .needClientAuth(true)
            .trustStorePath(WIREMOCK_TRUSTSTORE.getPath())
            .trustStorePassword("test123456")
            .trustStoreType("PKCS12")
        );
        
        var ctx = SimpleSSLContext.newBuilder()
                .withTrustStore(CLIENT_TRUSTSTORE.toPath(), "test123456".toCharArray())
                .build();
        
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .sslContext(ctx)
                .build();

        IOException ex = catchThrowableOfType(() -> { 
            client.send(request, HttpResponse.BodyHandlers.ofString()); 
        }, IOException.class);
        
        assertThat(ex).isExactlyInstanceOf(IOException.class)
                .hasMessage("HTTP/1.1 header parser received no bytes");
    }
    
    @Test
    @DisplayName("Should pass mTLS exchange when both sides trust each other.")
    void Should_PassMTLSExchange_When_BothSidesTrustEachOther() throws Exception {
        startNewServer(new WireMockConfiguration()
            .port(8080)
            .httpsPort(8443)
            .keystorePath(WIREMOCK_KEYSTORE.getPath())
            .keystorePassword("test")
            .keystoreType("PKCS12")
            .keyManagerPassword("test")
            .needClientAuth(true)
            .trustStorePath(WIREMOCK_TRUSTSTORE.getPath())
            .trustStorePassword("test123456")
            .trustStoreType("PKCS12")
        );
        
        var ctx = SimpleSSLContext.newBuilder()
                .withKeyStore(CLIENT_KEYSTORE.toPath(), "test".toCharArray())
                .withTrustStore(CLIENT_TRUSTSTORE.toPath(), "test123456".toCharArray())
                .build();
        
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .sslContext(ctx)
                .build();

        HttpResponse<String> response
                = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals("Hello World!", response.body());
    }
    
    @Test
    @DisplayName("Should pass mTLS exchange using PEM when both sides trust each other.")
    void Should_PassMTLSExchangeUsingPEM_When_BothSidesTrustEachOther() throws Exception {
        startNewServer(new WireMockConfiguration()
            .port(8080)
            .httpsPort(8443)
            .keystorePath(WIREMOCK_KEYSTORE.getPath())
            .keystorePassword("test")
            .keystoreType("PKCS12")
            .keyManagerPassword("test")
            .needClientAuth(true)
            .trustStorePath(WIREMOCK_TRUSTSTORE.getPath())
            .trustStorePassword("test123456")
            .trustStoreType("PKCS12")
        );
        
        var ctx = SimpleSSLContext.newPEMContextBuilder()
                .withPrivateKey(CLIENT_KEY.toPath(), CLIENT_CERT.toPath())
                .withPublicKey(WIREMOCK_CERT.toPath())
                .build();
        
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .sslContext(ctx)
                .build();

        HttpResponse<String> response
                = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals("Hello World!", response.body());
    }
}