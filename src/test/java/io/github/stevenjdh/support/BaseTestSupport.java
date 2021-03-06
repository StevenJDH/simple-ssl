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

package io.github.stevenjdh.support;

import io.github.stevenjdh.extensions.BenchmarkExtension;
import java.io.File;
import java.nio.file.Path;
import java.util.logging.Logger;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(BenchmarkExtension.class)
public abstract class BaseTestSupport {

    protected static final Path BASE_DIR = Path.of("target", "test-classes", "test-data");
    protected static final Path BADSSL_DIR = BASE_DIR.resolve("BadSSL.com");
    protected static final File BADSSL_TRUSTSTORE_PKCS12 = BADSSL_DIR.resolve("badssl-truststore.p12").toFile();
    protected static final File BADSSL_TRUSTSTORE_JKS = BADSSL_DIR.resolve("badssl-truststore.jks").toFile();
    protected static final File BADSSL_COM_CHAIN = BADSSL_DIR.resolve("badssl-com-chain.pem").toFile();
    protected static final File UNTRUSTED_ROOT_BADSSL_COM = BADSSL_DIR.resolve("untrusted-root.badssl.com.pem").toFile();
    protected static final Path WIREMOCK_DIR = BASE_DIR.resolve("WireMock");
    protected static final File CLIENT_CERT = WIREMOCK_DIR.resolve("client.crt").toFile();
    protected static final File CLIENT_KEY = WIREMOCK_DIR.resolve("client.key").toFile();
    protected static final File CLIENT_ENCRYPTED_KEY = WIREMOCK_DIR.resolve("client-encrypted.key").toFile();
    protected static final File WIREMOCK_CERT = WIREMOCK_DIR.resolve("wiremock.crt").toFile();
    protected static final File WIREMOCK_KEY = WIREMOCK_DIR.resolve("wiremock.key").toFile();
    protected static final File WIREMOCK_TRUSTSTORE = WIREMOCK_DIR.resolve("wiremock-truststore.p12").toFile();
    protected static final File WIREMOCK_KEYSTORE = WIREMOCK_DIR.resolve("wiremock-keystore.p12").toFile();
    protected static final File CLIENT_TRUSTSTORE = WIREMOCK_DIR.resolve("client-truststore.p12").toFile();
    protected static final File CLIENT_KEYSTORE = WIREMOCK_DIR.resolve("client-keystore.p12").toFile();
    protected static final Path OUTPUT_DIR = BASE_DIR.resolve("output");
    protected static final File TRUSTSTORE_OUTPUT = OUTPUT_DIR.resolve("truststore-test.p12").toFile();
    protected static final File KEYSTORE_OUTPUT = OUTPUT_DIR.resolve("keystore-test.p12").toFile();
    
    protected static Logger getFormattedLogger(String name) {
        System.setProperty("java.util.logging.SimpleFormatter.format",
                "[%1$tF %1$tT] [%4$-7s] %5$s %n");
        return Logger.getLogger(name);
    }
}