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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.services.kms.MockKMSClient;

public class EncryptionHandlerTest {
    private final CryptoAlgorithm cryptoAlgorithm_ = AwsCrypto.getDefaultCryptoAlgorithm();
    private final int frameSize_ = AwsCrypto.getDefaultFrameSize();
    private final Map<String, String> encryptionContext_ = Collections.<String, String> emptyMap();
    private final MockKMSClient mockKMSClient = new MockKMSClient();
    private final String cmkId = mockKMSClient.createKey().getKeyMetadata().getKeyId();
    private final KmsMasterKeyProvider provider_ = new MockKmsProvider(mockKMSClient);
    private final KmsMasterKey customerMasterKey_ = provider_.getMasterKey(cmkId);
    private final List<KmsMasterKey> cmks_ = Collections.singletonList(customerMasterKey_);

    @Test(expected = NullPointerException.class)
    public void nullMasterKey() {
        new EncryptionHandler<>(null, encryptionContext_, cryptoAlgorithm_, frameSize_);
    }

    @Test(expected = NullPointerException.class)
    public void nullEncryptionContext() {
        new EncryptionHandler<>(cmks_, null, cryptoAlgorithm_, frameSize_);
    }

    @Test(expected = NullPointerException.class)
    public void nullCryptoAlgorithm() {
        new EncryptionHandler<>(cmks_, encryptionContext_, null, frameSize_);
    }

    @Test(expected = AwsCryptoException.class)
    public void negativeFrameSize() {
        new EncryptionHandler<>(cmks_, encryptionContext_, cryptoAlgorithm_, -1);
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidLenProcessBytes() {
        final EncryptionHandler<KmsMasterKey> encryptionHandler = new EncryptionHandler<>(
                cmks_,
                encryptionContext_,
                cryptoAlgorithm_,
                frameSize_);

        final byte[] in = new byte[1];
        final byte[] out = new byte[1];
        encryptionHandler.processBytes(in, 0, -1, out, 0);
    }

    @Test(expected = AwsCryptoException.class)
    public void invalidOffsetProcessBytes() {
        final EncryptionHandler<KmsMasterKey> encryptionHandler = new EncryptionHandler<>(
                cmks_,
                encryptionContext_,
                cryptoAlgorithm_,
                frameSize_);

        final byte[] in = new byte[1];
        final byte[] out = new byte[1];
        encryptionHandler.processBytes(in, -1, in.length, out, 0);
    }
}