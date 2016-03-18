/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 * 
 * http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.internal;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Internal utility methods.
 */
public final class Utils {
    private Utils() {
        // Prevent instantiation
    }

    /**
     * Throws {@link NullPointerException} with message {@code paramName} if {@code object} is null.
     *
     * @param object
     *            value to be null-checked
     * @param paramName
     *            message for the potential {@link NullPointerException}
     * @return {@code object}
     * @throws NullPointerException
     *             if {@code object} is null
     */
    public static <T> T assertNonNull(final T object, final String paramName) throws NullPointerException {
        if (object == null) {
            throw new NullPointerException(paramName + " must not be null");
        }
        return object;
    }

    /**
     * Returns a possibly truncated version of {@code arr} which is guaranteed to be exactly
     * {@code len} elements long. If {@code arr} is already exactly {@code len} elements long, then
     * {@code arr} is returned without copy or modification. If {@code arr} is longer than
     * {@code len}, then a truncated copy is returned. If {@code arr} is shorter than {@code len}
     * then this throws an {@link IllegalArgumentException}.
     */
    public static byte[] truncate(final byte[] arr, final int len) throws IllegalArgumentException {
        if (arr.length == len) {
            return arr;
        } else if (arr.length > len) {
            return Arrays.copyOf(arr, len);
        } else {
            throw new IllegalArgumentException("arr is not at least " + len + " elements long");
        }
    }

    /**
     * Generate the AAD bytes to use when encrypting/decrypting content. The
     * generated AAD is a block of bytes containing the provided message
     * identifier, the string identifier, the sequence number, and the length of
     * the content.
     * 
     * @param messageId
     *            the unique message identifier for the ciphertext.
     * @param idString
     *            the string describing the type of content processed.
     * @param seqNum
     *            the sequence number.
     * @param len
     *            the length of the content.
     * @return
     *         the bytes containing the generated AAD.
     */
    static byte[] generateContentAad(final byte[] messageId, final String idString, final int seqNum, final long len) {
        final byte[] idBytes = idString.getBytes(StandardCharsets.UTF_8);
        final int aadLen = messageId.length + idBytes.length + Integer.SIZE / Byte.SIZE + Long.SIZE / Byte.SIZE;
        final ByteBuffer aad = ByteBuffer.allocate(aadLen);
    
        aad.put(messageId);
        aad.put(idBytes);
        aad.putInt(seqNum);
        aad.putLong(len);
    
        return aad.array();
    }
}
