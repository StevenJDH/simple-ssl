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

package io.github.stevenjdh.simple.exceptions;

/**
 * This exception indicates one of a variety of certificate problems.
 */
public class GenericKeyStoreException extends RuntimeException {

    /**
     * Constructs a Generic KeyStore exception with no detail message. A detail
     * message is a String that describes this particular exception.
     */
    public GenericKeyStoreException() {
        super();
    }

    /**
     * Constructs a Generic KeyStore exception with the given detail
     * message. A detail message is a String that describes this
     * particular exception.
     *
     * @param msg the detail message.
     */
    public GenericKeyStoreException(String msg) {
        super(msg);
    }

    /**
     * Creates a {@code GenericKeyStoreException} with the specified
     * detail message and cause.
     *
     * @param message the detail message (which is saved for later retrieval
     *        by the {@link #getMessage()} method).
     * @param cause the cause (which is saved for later retrieval by the
     *        {@link #getCause()} method).  (A {@code null} value is permitted,
     *        and indicates that the cause is nonexistent or unknown.)
     * @since 1.5
     */
    public GenericKeyStoreException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a {@code GenericKeyStoreException} with the specified cause
     * and a detail message of {@code (cause==null ? null : cause.toString())}
     * (which typically contains the class and detail message of
     * {@code cause}).
     *
     * @param cause the cause (which is saved for later retrieval by the
     *        {@link #getCause()} method).  (A {@code null} value is permitted,
     *        and indicates that the cause is nonexistent or unknown.)
     * @since 1.5
     */
    public GenericKeyStoreException(Throwable cause) {
        super(cause);
    }
}