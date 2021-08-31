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

package io.github.stevenjdh.simple.exceptions;

import io.github.stevenjdh.extensions.BenchmarkExtension;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(BenchmarkExtension.class)
class GenericKeyStoreExceptionTest {

    private static final String TEST_MESSAGE = "This is a test.";
    private static final String CAUSE_MESSAGE = "It was me!";
    private static final Exception CAUSE_EX = new Exception(CAUSE_MESSAGE);

    @Test
    @DisplayName("Should have null message and no cause when thrown without args.")
    void Should_HaveNullMessageAndNoCause_When_ThrownWithoutArgs() {
        assertThatExceptionOfType(GenericKeyStoreException.class)
                .isThrownBy(() -> { throw new GenericKeyStoreException(); })
                .matches(e -> e.getMessage() == null, "message should be null")
                .isInstanceOf(RuntimeException.class)
                .withNoCause();
    }

    @Test
    @DisplayName("Should have message and no cause when thrown with String arg.")
    void Sould_HaveMessageAndNoCause_When_ThrownWithStringArg() {
        assertThatExceptionOfType(GenericKeyStoreException.class)
                .isThrownBy(() -> { throw new GenericKeyStoreException(TEST_MESSAGE); })
                .withMessage(TEST_MESSAGE)
                .withNoCause();
    }

    @Test
    @DisplayName("Should have message and cause when thrown with all args.")
    void Sould_HaveMessageAndCause_When_ThrownWithAllArgs() {
        assertThatExceptionOfType(GenericKeyStoreException.class)
                .isThrownBy(() -> { throw new GenericKeyStoreException(TEST_MESSAGE, CAUSE_EX); })
                .withMessage(TEST_MESSAGE)
                .withRootCauseExactlyInstanceOf(Exception.class)
                .havingRootCause()
                .withMessage(CAUSE_MESSAGE);
    }
    
    @Test
    @DisplayName("Should have message referencing cause when thrown with cause arg.")
    void Should_HaveMessageReferencingCause_When_ThrownWithCauseArg() {
        assertThatExceptionOfType(GenericKeyStoreException.class)
                .isThrownBy(() -> { throw new GenericKeyStoreException(CAUSE_EX); })
                .withMessageStartingWith("java.lang.Exception:")
                .withCauseExactlyInstanceOf(Exception.class)
                .havingRootCause()
                .withMessage(CAUSE_MESSAGE);
    }
}