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

import static org.junit.Assert.assertEquals;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;

public class FrameEncryptionHandlerTest {
    private final CryptoAlgorithm cryptoAlgorithm_ = AwsCrypto.getDefaultCryptoAlgorithm();
    private final byte[] messageId_ = RandomBytesGenerator.generate(Constants.MESSAGE_ID_LEN);
    private final byte nonceLen_ = cryptoAlgorithm_.getNonceLen();
    private final byte[] dataKeyBytes_ = RandomBytesGenerator.generate(cryptoAlgorithm_.getKeyLength());
    private final SecretKey encryptionKey_ = new SecretKeySpec(dataKeyBytes_, "AES");
    private final int frameSize_ = AwsCrypto.getDefaultFrameSize();

    private final FrameEncryptionHandler frameEncryptionHandler_ = new FrameEncryptionHandler(
            encryptionKey_,
            nonceLen_,
            cryptoAlgorithm_,
            messageId_,
            frameSize_);

    @Test
    public void emptyOutBytes() {
        final int outLen = 0;
        final byte[] out = new byte[outLen];
        final int processedLen = frameEncryptionHandler_.doFinal(out, 0);
        assertEquals(outLen, processedLen);
    }
}