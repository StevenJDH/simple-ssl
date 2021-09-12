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

package io.github.stevenjdh.simple.git;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;

public final class BuildInfo {
    
    private final ObjectMapper mapper;
    
    public BuildInfo() {
        this(new ObjectMapper());
    }
    
    public BuildInfo(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public GitProperties getGitProperties() {
        try (var is = getClass().getClassLoader()
                .getResourceAsStream("git.properties")) {
            return mapper.readValue(is, GitProperties.class);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex.getMessage(), ex);
        }
    }
}