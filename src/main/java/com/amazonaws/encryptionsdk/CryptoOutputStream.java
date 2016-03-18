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

package com.amazonaws.encryptionsdk;

import java.io.IOException;
import java.io.OutputStream;

import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.MessageCryptoHandler;
import com.amazonaws.encryptionsdk.internal.Utils;

/**
 * A CryptoOutputStream is a subclass of java.io.OutputStream. It performs cryptographic
 * transformation of the bytes passing through it.
 * 
 * <p>
 * The CryptoOutputStream wraps a provided OutputStream object and performs cryptographic
 * transformation of the bytes written to it. The transformed bytes are then written to the wrapped
 * OutputStream. It uses the cryptography handler provided during construction to invoke methods
 * that perform the cryptographic transformations.
 * 
 * <p>
 * In short, writing to the CryptoOutputStream results in those bytes being cryptographically
 * transformed and written to the wrapped OutputStream.
 * 
 * <p>
 * For example, if the crypto handler provides methods for decryption, the CryptoOutputStream will
 * decrypt the provided ciphertext bytes and write the plaintext bytes to the wrapped OutputStream.
 * 
 * <p>
 * This class adheres strictly to the semantics, especially the failure semantics, of its ancestor
 * class java.io.OutputStream. This class overrides all the methods specified in its ancestor class.
 * 
 * <p>
 * To instantiate an instance of this class, please see {@link AwsCrypto}.
 * 
 * @param <K>
 *            The type of {@link MasterKey}s used to manipulate the data.
 */
public class CryptoOutputStream<K extends MasterKey<K>> extends OutputStream {
    private final OutputStream outputStream_;
    private int lastProcessedLen_ = 0;

    private byte[] outBytes_ = new byte[0];
    private final MessageCryptoHandler<K> cryptoHandler_;

    /**
     * Constructs a CryptoOutputStream that wraps the provided OutputStream object. It performs
     * cryptographic transformation of the bytes written to it using the methods provided in the
     * provided CryptoHandler implementation. The transformed bytes are then written to the wrapped
     * OutputStream.
     * 
     * @param outputStream
     *            the outputStream object to be wrapped.
     * @param cryptoHandler
     *            the cryptoHandler implementation that provides the methods to use in performing
     *            cryptographic transformation of the bytes written to this stream.
     */
    CryptoOutputStream(final OutputStream outputStream, final MessageCryptoHandler<K> cryptoHandler) {
        outputStream_ = Utils.assertNonNull(outputStream, "outputStream");
        cryptoHandler_ = Utils.assertNonNull(cryptoHandler, "cryptoHandler");
    }

    /**
     * {@inheritDoc}
     * 
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid or corrupt
     *             ciphertext.
     */
    @Override
    public void write(final byte[] b) throws IllegalArgumentException, IOException, BadCiphertextException {
        if (b == null) {
            throw new IllegalArgumentException("b cannot be null");
        }
        write(b, 0, b.length);
    }

    /**
     * {@inheritDoc}
     * 
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid or corrupt
     *             ciphertext.
     */
    @Override
    public void write(final byte[] b, final int off, final int len) throws IllegalArgumentException, IOException,
            BadCiphertextException {
        if (b == null) {
            throw new IllegalArgumentException("b cannot be null");
        }

        if (len < 0 || off < 0) {
            throw new IllegalArgumentException(String.format("Invalid values for offset: %d and length: %d", off, len));
        }

        final int outLen = cryptoHandler_.estimateOutputSize(len);
        outBytes_ = new byte[outLen];

        lastProcessedLen_ = cryptoHandler_.processBytes(b, off, len, outBytes_, 0).getBytesWritten();
        if (lastProcessedLen_ > 0) {
            outputStream_.write(outBytes_, 0, lastProcessedLen_);
        }
    }

    /**
     * {@inheritDoc}
     * 
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid or corrupt
     *             ciphertext.
     */
    @Override
    public void write(int b) throws IOException, BadCiphertextException {
        byte[] bArray = new byte[1];
        bArray[0] = (byte) b;
        write(bArray, 0, 1);
    }

    /**
     * Closes this output stream and releases any system resources associated
     * with this stream.
     * 
     * <p>
     * This method writes any final bytes to the underlying stream that complete
     * the cyptographic transformation of the written bytes. It also calls close
     * on the wrapped OutputStream.
     * 
     * @throws IOException
     *             if an I/O error occurs.
     * @throws BadCiphertextException
     *             This is thrown only during decryption if b contains invalid
     *             or corrupt ciphertext.
     */
    @Override
    public void close() throws IOException, BadCiphertextException {
        if (outBytes_.length == 0) {
            outBytes_ = new byte[cryptoHandler_.estimateOutputSize(0)];
            lastProcessedLen_ = 0;
        }
        int finalLen = cryptoHandler_.doFinal(outBytes_, lastProcessedLen_);

        outputStream_.write(outBytes_, lastProcessedLen_, finalLen);
        outputStream_.close();
    }

    /**
     * Returns the result of the cryptographic operations including associate metadata.
     */
    public CryptoResult<CryptoOutputStream<K>, K> getCryptoResult() {
        return new CryptoResult<CryptoOutputStream<K>, K>(
                this,
                cryptoHandler_.getMasterKeys(),
                cryptoHandler_.getHeaders());
    }
}