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

package io.github.stevenjdh.simple.git;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class BuildInfoTest {
    
    @Mock
    private ObjectMapper mapper;
    
    @InjectMocks
    private BuildInfo buildInfo;
    
    @Test
    @DisplayName("Should throw UncheckedIOException for IO related problems.")
    void Should_ThrowUncheckedIOException_ForIORelatedProblems() throws IOException {
        String causeMessage = "This is a test.";
        when(mapper.readValue(isA(InputStream.class), eq(GitProperties.class)))
                .thenThrow(new IOException(causeMessage));
        
        assertThatExceptionOfType(UncheckedIOException.class)
                .isThrownBy(() -> buildInfo.getGitProperties())
                .withRootCauseExactlyInstanceOf(IOException.class)
                .havingRootCause()
                .withMessage(causeMessage);
    }
}