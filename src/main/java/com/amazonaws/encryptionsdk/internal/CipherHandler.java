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

import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;

/**
 * This class provides a cryptographic cipher handler powered by an underlying block cipher. The
 * block cipher performs authenticated encryption of the provided bytes using Additional
 * Authenticated Data (AAD).
 *
 * <p>
 * This class implements a method called cipherData() that encrypts or decrypts a byte array by
 * calling methods on the underlying block cipher.
 */
class CipherHandler {
    private final Cipher cipher_;

    /**
     * Create a cipher handler for processing bytes using an underlying block cipher.
     *
     * @param key
     *            the key to use in encrypting or decrypting bytes
     * @param nonce
     *            the nonce to be used by the underlying cipher
     * @param tagLenBits
     *            the tag length in bits to set in the underlying cipher
     * @param contentAad
     *            the optional additional authentication data to be used by the underlying cipher
     * @param mode
     *            the mode for processing the bytes as defined in
     *            {@link Cipher#init(int, java.security.Key)}
     * @param cryptoAlgorithm
     *            the cryptography algorithm to be used by the underlying block cipher.
     * @throws GeneralSecurityException
     */
    CipherHandler(final SecretKey key, final byte[] nonce, final byte[] contentAad,
            final int cipherMode, final CryptoAlgorithm cryptoAlgorithm) {
        if (nonce.length != cryptoAlgorithm.getNonceLen()) {
            throw new IllegalArgumentException("Invalid nonce length: " + nonce.length);
        }

        final AlgorithmParameterSpec spec = new GCMParameterSpec(cryptoAlgorithm.getTagLen() * 8, nonce, 0, nonce.length);

        try {
            cipher_ = buildCipherObject(cryptoAlgorithm);
            cipher_.init(cipherMode, key, spec);
            if (contentAad != null) {
                cipher_.updateAAD(contentAad);
            }
        } catch (final GeneralSecurityException gsx) {
            throw new AwsCryptoException(gsx);
        }
    }

    private static Cipher buildCipherObject(final CryptoAlgorithm alg) {
        try {
            // Right now, just GCM is supported
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (final GeneralSecurityException ex) {
            throw new IllegalStateException("Java does not support the requested algorithm", ex);
        }
    }

    /**
     * Process data through the cipher.
     *
     * <p>
     * This method calls the <code>update</code> and <code>doFinal</code> methods on the underlying
     * cipher to complete processing of the data.
     *
     * @param content
     *            the content to be processed by the underlying cipher
     * @param off
     *            the offset into content array to be processed
     * @param len
     *            the number of bytes to process
     * @return the bytes processed by the underlying cipher
     * @throws BadCiphertextException
     *             if any of the methods called on the underlying cipher fails
     */
    synchronized byte[] cipherData(final byte[] content, final int off, final int len) throws BadCiphertextException {
        final int cipherOutLen = cipher_.getOutputSize(len);
        final byte[] cipherOut = new byte[cipherOutLen];

        try {
            final int processedSize = cipher_.update(content, off, len, cipherOut, 0);
            cipher_.doFinal(cipherOut, processedSize);
        } catch (final GeneralSecurityException e) {
            throw new BadCiphertextException(e);
        }

        return cipherOut;
    }
}
