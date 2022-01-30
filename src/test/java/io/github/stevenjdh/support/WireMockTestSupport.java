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

import com.github.tomakehurst.wiremock.WireMockServer;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import java.util.logging.Logger;
import wiremock.org.apache.hc.core5.http.HttpHeaders;
import wiremock.org.apache.hc.core5.http.HttpStatus;

public class WireMockTestSupport extends BaseTestSupport {

    private static final Logger LOG = getFormattedLogger(WireMockTestSupport.class.getName());
    private WireMockServer wireMockServer;
    protected static final String MEDIATYPE_TEXT_PLAIN = "text/plain";

    public void startNewServer(WireMockConfiguration config) {
        stop();
        wireMockServer = new WireMockServer(config);
        
        wireMockServer.stubFor(get("/test")
                .withHeader(HttpHeaders.ACCEPT, equalTo(MEDIATYPE_TEXT_PLAIN))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MEDIATYPE_TEXT_PLAIN)
                        .withStatus(HttpStatus.SC_OK)
                        .withBody("Hello World!")));
        
        wireMockServer.start();
        LOG.info("Started new WireMock instance with provided configuration.");
    }

    public void start() {
        if (wireMockServer == null) {
            LOG.warning("No instance of WireMock detected. Creating one with default configuration.");
            wireMockServer = new WireMockServer(getDefaultConfig());
        }
        wireMockServer.start();
        LOG.info("Started WireMock instance with existing configuration.");
    }

    public void stop() {
        if (wireMockServer != null && wireMockServer.isRunning()) {
            wireMockServer.stop();
            LOG.info("Stopped running instance of WireMock.");
        }
    }

    private WireMockConfiguration getDefaultConfig() {
        return new WireMockConfiguration()
                .port(8080)
                .httpsPort(8443);
    }
}