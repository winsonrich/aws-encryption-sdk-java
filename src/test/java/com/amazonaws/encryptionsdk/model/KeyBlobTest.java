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

package com.amazonaws.encryptionsdk.model;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.internal.RandomBytesGenerator;
import com.amazonaws.encryptionsdk.internal.StaticMasterKey;

public class KeyBlobTest {
    private static CryptoAlgorithm ALGORITHM = CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_NO_KDF;
    final String providerId_ = "Test Key";
    final String providerInfo_ = "Test Info";
    private StaticMasterKey masterKeyProvider_;

    @Before
    public void init() {
        masterKeyProvider_ = new StaticMasterKey("testmaterial");
    }

    private byte[] createKeyBlobBytes() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Test Encryption Context");
        final DataKey<StaticMasterKey> mockDataKey_ = masterKeyProvider_.generateDataKey(ALGORITHM, encryptionContext);

        final KeyBlob keyBlob = new KeyBlob(
                providerId_,
                providerInfo_.getBytes(StandardCharsets.UTF_8),
                mockDataKey_.getEncryptedDataKey());

        return keyBlob.toByteArray();
    }

    private KeyBlob deserialize(final byte[] keyBlobBytes) {
        final KeyBlob reconstructedKeyBlob = new KeyBlob();
        reconstructedKeyBlob.deserialize(keyBlobBytes, 0);
        return reconstructedKeyBlob;
    }

    @Test
    public void serializeDeserialize() {
        final byte[] keyBlobBytes = createKeyBlobBytes();

        final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);
        final byte[] reconstructedKeyBlobBytes = reconstructedKeyBlob.toByteArray();

        assertArrayEquals(reconstructedKeyBlobBytes, keyBlobBytes);
    }

    @Test(expected = AwsCryptoException.class)
    public void overlyLargeKeyProviderIdLen() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Test Encryption Context");

        final DataKey<StaticMasterKey> mockDataKey = masterKeyProvider_.generateDataKey(ALGORITHM, encryptionContext);

        final int providerId_Len = Short.MAX_VALUE + 1;
        final byte[] providerId_Bytes = RandomBytesGenerator.generate(providerId_Len);
        final String providerId_ = new String(providerId_Bytes, StandardCharsets.UTF_8);

        final String providerInfo_ = "Test Info";

        new KeyBlob(providerId_, providerInfo_.getBytes(StandardCharsets.UTF_8), mockDataKey.getEncryptedDataKey());

    }

    @Test(expected = AwsCryptoException.class)
    public void overlyLargeKeyProviderInfoLen() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Test Encryption Context");

        final DataKey<StaticMasterKey> mockDataKey = masterKeyProvider_.generateDataKey(ALGORITHM, encryptionContext);

        final int providerInfo_Len = Short.MAX_VALUE + 1;
        final byte[] providerInfo_ = RandomBytesGenerator.generate(providerInfo_Len);

        new KeyBlob(providerId_, providerInfo_, mockDataKey.getEncryptedDataKey());
    }

    @Test(expected = AwsCryptoException.class)
    public void overlyLargeKey() {
        final int keyLen = Short.MAX_VALUE + 1;
        final byte[] encryptedKeyBytes = RandomBytesGenerator.generate(keyLen);

        new KeyBlob(providerId_, providerInfo_.getBytes(StandardCharsets.UTF_8), encryptedKeyBytes);
    }

    @Test
    public void deserializeNull() {
        final KeyBlob keyBlob = new KeyBlob();
        final int deserializedBytes = keyBlob.deserialize(null, 0);

        assertEquals(0, deserializedBytes);
    }

    @Test
    public void checkKeyProviderIdLen() {
        final byte[] keyBlobBytes = createKeyBlobBytes();

        final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

        assertEquals(providerId_.length(), reconstructedKeyBlob.getKeyProviderIdLen());
    }

    @Test
    public void checkKeyProviderId() {
        final byte[] keyBlobBytes = createKeyBlobBytes();

        final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

        assertArrayEquals(providerId_.getBytes(StandardCharsets.UTF_8), reconstructedKeyBlob
                .getProviderId()
                .getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void checkKeyProviderInfoLen() {
        final byte[] keyBlobBytes = createKeyBlobBytes();

        final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

        assertEquals(providerInfo_.length(), reconstructedKeyBlob.getKeyProviderInfoLen());
    }

    @Test
    public void checkKeyProviderInfo() {
        final byte[] keyBlobBytes = createKeyBlobBytes();

        final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

        assertArrayEquals(providerInfo_.getBytes(StandardCharsets.UTF_8), reconstructedKeyBlob.getProviderInformation());
    }

    @Test
    public void checkKeyLen() {
        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Test Encryption Context");
        final DataKey<StaticMasterKey> mockDataKey_ = masterKeyProvider_.generateDataKey(ALGORITHM, encryptionContext);

        final KeyBlob keyBlob = new KeyBlob(
                providerId_,
                providerInfo_.getBytes(StandardCharsets.UTF_8),
                mockDataKey_.getEncryptedDataKey());

        final byte[] keyBlobBytes = keyBlob.toByteArray();

        final KeyBlob reconstructedKeyBlob = deserialize(keyBlobBytes);

        assertEquals(mockDataKey_.getEncryptedDataKey().length, reconstructedKeyBlob.getEncryptedDataKeyLen());
    }

    private byte[] negativeKeyProviderIdLenTestVector() {
	// key provider id len of -1, key provider info len of 2, and key len of 3
        return new byte[]{
            (byte)0xff, (byte)0xff, (byte)0x01, (byte)0x00, (byte)0x02, (byte)0x02, (byte)0x03,
	    (byte)0x00, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06
        };
    }

    private byte[] negativeKeyProviderInfoLenTestVector() {
	// key provider id len of 1, key provider info len of -2, key len of 3
        return new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x01, (byte)0xff, (byte)0xfe, (byte)0x02, (byte)0x03,
            (byte)0x00, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06
        };
    }

    private byte[] negativeKeyLenTestVector() {
	// key provider id len of 1, key provider info len of 2, key len of -3
        return new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x03,
            (byte)0xff, (byte)0xfd, (byte)0x04, (byte)0x05, (byte)0x06
        };
    }

    private void assertIncomplete(final byte[] vector) {
	assertFalse(deserialize(vector).isComplete());
    }
    
    @Test
    public void checkNegativeKeyProviderIdLen() {
        final byte[] keyBlobBytes = createKeyBlobBytes();

        // manually set the keyProviderIdLen to negative
        final byte[] negativeKeyProviderIdLen = ByteBuffer.allocate(Short.BYTES)
	    .putShort((short) -1).array();
        System.arraycopy(negativeKeyProviderIdLen, 0, keyBlobBytes, 0, Short.BYTES);

	// a negative field length throws a parse exception, so deserialization is incomplete
	assertIncomplete(keyBlobBytes);
	assertIncomplete(negativeKeyProviderIdLenTestVector());
    }

    @Test
    public void checkNegativeKeyProviderInfoLen() {
        final byte[] keyBlobBytes = createKeyBlobBytes();

        // manually set the keyProviderInfoLen to negative
        final byte[] negativeKeyProviderInfoLen = ByteBuffer.allocate(Short.BYTES)
	    .putShort((short) -1).array();
	int offset = Short.BYTES + providerId_.length();
        System.arraycopy(negativeKeyProviderInfoLen, 0, keyBlobBytes, offset, Short.BYTES);

       	// a negative field length throws a parse exception, so deserialization is incomplete
	assertIncomplete(keyBlobBytes);
	assertIncomplete(negativeKeyProviderInfoLenTestVector());
    }

    @Test
    public void checkNegativeKeyLen() {
        final byte[] keyBlobBytes = createKeyBlobBytes();

        // we will manually set the keyLen to negative
        final byte[] negativeKeyLen = ByteBuffer.allocate(Short.BYTES)
	    .putShort((short) -1).array();
        int offset = Short.BYTES + providerId_.length() + Short.BYTES + providerInfo_.length();
        System.arraycopy(negativeKeyLen, 0, keyBlobBytes, offset, Short.BYTES);

        // negative key len throws parse exception so deserialization is incomplete
	assertIncomplete(keyBlobBytes);
	assertIncomplete(negativeKeyLenTestVector());
    }
}
