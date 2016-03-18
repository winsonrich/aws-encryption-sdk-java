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

package com.amazonawsencryptionsdk;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoInputStream;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;

public class CryptoInputStreamTest {
    private static final SecureRandom RND = new SecureRandom();
    private MasterKey<JceMasterKey> customerMasterKey;
    private AwsCrypto encryptionClient_;
    private Path sandbox_;
    private String sandboxPath_;

    @Before
    public void setup() throws IOException {
        byte[] rawKey = new byte[16];
        RND.nextBytes(rawKey);
        customerMasterKey = JceMasterKey.getInstance(new SecretKeySpec(rawKey, "AES"), "mockProvider", "mockKey",
                "AES/GCM/NoPadding");
        encryptionClient_ = new AwsCrypto();

        sandbox_ = Files.createTempDirectory(null);
        sandboxPath_ = sandbox_.toString() + "/";
    }

    @After
    public void cleanup() {
        TestIOUtils.deleteDir(sandbox_.toFile());
    }

    private void doEncryptDecrypt(final int byteSize, final int frameSize, final int readLen) throws IOException {
        final String inputFileName = sandboxPath_ + "plaintext_" + byteSize + ".txt";
        final String encryptedFileName = new String(inputFileName + ".enc");
        final String decryptedFileName = new String(inputFileName + ".dec");

        TestIOUtils.generateFile(inputFileName, byteSize);

        final byte[] originalDigest = TestIOUtils.computeFileDigest(inputFileName);

        encryptionClient_.setEncryptionFrameSize(frameSize);

        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        // encryption
        InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);
        OutputStream outStream = new FileOutputStream(encryptedFileName);

        TestIOUtils.copyInStreamToOutStream(encryptionInStream, outStream, readLen);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        final InputStream decryptionInStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                inStream);
        outStream = new FileOutputStream(decryptedFileName);

        TestIOUtils.copyInStreamToOutStream(decryptionInStream, outStream, readLen);

        final byte[] digestAfterDecryption = TestIOUtils.computeFileDigest(decryptedFileName);

        assertArrayEquals(originalDigest, digestAfterDecryption);
    }

    @Test
    public void encryptDecrypt() throws IOException {
        for (final CryptoAlgorithm cryptoAlg : EnumSet.allOf(CryptoAlgorithm.class)) {
            final int blockSize = cryptoAlg.getBlockSize();
            final int[] frameSizeToTest = { 0, blockSize, blockSize * 2, blockSize * 10,
                    AwsCrypto.getDefaultFrameSize() };

            // iterate over frame size to test
            for (int i = 0; i < frameSizeToTest.length; i++) {
                final int frameSize = frameSizeToTest[i];
                int[] bytesToTest = { 0, 1, frameSize - 1, frameSize, frameSize + 1, (int) (frameSize * 1.5),
                        frameSize * 2, 1000000 };

                // iterate over byte size to test
                for (int j = 0; j < bytesToTest.length; j++) {
                    final int byteSize = bytesToTest[j];
                    int[] readLenVals = { 1, byteSize - 1, byteSize, byteSize + 1, byteSize * 2, 1000000 };

                    // iterate over read lengths to test
                    for (int k = 0; k < readLenVals.length; k++) {
                        final int readLen = readLenVals[k];
                        if (byteSize >= 0 && readLen > 0) {
                            doEncryptDecrypt(byteSize, frameSize, readLen);
                        }
                    }
                }
            }
        }
    }

    @Test
    public void doEncryptDecryptWithoutEncContext() throws IOException {
        final int byteSize = 1000000;
        final String inputFileName = sandboxPath_ + "plaintext_" + byteSize + ".txt";
        final String encryptedFileName = new String(inputFileName + ".enc");
        final String decryptedFileName = new String(inputFileName + ".dec");

        TestIOUtils.generateFile(inputFileName, byteSize);
        final byte[] originalDigest = TestIOUtils.computeFileDigest(inputFileName);

        final int frameSize = AwsCrypto.getDefaultFrameSize();
        encryptionClient_.setEncryptionFrameSize(frameSize);

        // encryption
        InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream);
        OutputStream outStream = new FileOutputStream(encryptedFileName);

        TestIOUtils.copyInStreamToOutStream(encryptionInStream, outStream);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        final InputStream decryptionInStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                inStream);
        outStream = new FileOutputStream(decryptedFileName);

        TestIOUtils.copyInStreamToOutStream(decryptionInStream, outStream);

        final byte[] digestAfterDecryption = TestIOUtils.computeFileDigest(decryptedFileName);

        assertArrayEquals(originalDigest, digestAfterDecryption);
    }

    @Test
    public void encryptAPIComptability() throws IOException {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final String inputFileName = sandboxPath_ + "plaintext_1MB.txt";
        final String encryptedFileName = new String(inputFileName + ".enc");

        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Test with %s" + inputFileName);

        encryptionClient_.setEncryptionFrameSize(AwsCrypto.getDefaultFrameSize());

        // encryption
        final CryptoResult<byte[], JceMasterKey> cipherText = encryptionClient_.encryptData(
                customerMasterKey,
                plaintextBytes,
                encryptionContext);

        final OutputStream outStream = new FileOutputStream(encryptedFileName);
        outStream.write(cipherText.getResult());
        outStream.close();

        // decryption
        final FileInputStream inStream = new FileInputStream(encryptedFileName);
        final InputStream decryptionInStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                inStream);

        final byte[] decryptedBytes = new byte[cipherText.getResult().length];
        int readLen = 0;
        int totalReadBytes = 0;
        while (readLen >= 0) {
            totalReadBytes += readLen;
            try {
                readLen = decryptionInStream.read(decryptedBytes, totalReadBytes, 1024);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        decryptionInStream.close();

        final byte[] outBytes = Arrays.copyOfRange(decryptedBytes, 0, totalReadBytes);

        assertArrayEquals(plaintextBytes, outBytes);
    }

    @Test
    public void decryptAPIComptability() throws IOException {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final String inputFileName = sandboxPath_ + "plaintext_1MB.txt";
        final String encryptedFileName = new String(inputFileName + ".enc");

        OutputStream outStream = new FileOutputStream(inputFileName);
        outStream.write(plaintextBytes);
        outStream.close();

        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Test with %s" + inputFileName);

        encryptionClient_.setEncryptionFrameSize(AwsCrypto.getDefaultFrameSize());

        // encryption
        InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);
        outStream = new FileOutputStream(encryptedFileName);

        TestIOUtils.copyInStreamToOutStream(encryptionInStream, outStream);
        encryptionInStream.close();
        outStream.close();

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        final int encryptedBytesLen = (int) encryptionClient_.estimateCiphertextSize(
                customerMasterKey,
                ptSize,
                encryptionContext);
        final byte[] encryptedBytes = new byte[encryptedBytesLen];

        int readLen = 0;
        int totalReadBytes = 0;
        while (readLen >= 0) {
            totalReadBytes += readLen;
            try {
                readLen = inStream.read(encryptedBytes);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        inStream.close();

        final byte[] outBytes = Arrays.copyOfRange(encryptedBytes, 0, totalReadBytes);
        final CryptoResult<byte[], JceMasterKey> decryptedText = encryptionClient_.decryptData(customerMasterKey,
                outBytes);

        assertArrayEquals(plaintextBytes, decryptedText.getResult());
    }

    @Test
    public void outputStreamComptability() throws IOException {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final String inputFileName = sandboxPath_ + "plaintext_1MB.txt";
        final String encryptedFileName = new String(inputFileName + ".enc");

        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final int frameSize = 4096;
        encryptionClient_.setEncryptionFrameSize(frameSize);

        // encryption
        OutputStream outStream = new FileOutputStream(encryptedFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);
        encryptionOutStream.write(plaintextBytes);
        encryptionOutStream.close();

        // decryption
        InputStream inStream = new FileInputStream(encryptedFileName);
        final InputStream decryptionInStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                inStream);

        final byte[] decryptedBytes = new byte[ptSize];
        int readLen = 0;
        int totalReadBytes = 0;
        while (readLen >= 0) {
            totalReadBytes += readLen;
            try {
                readLen = decryptionInStream.read(decryptedBytes, totalReadBytes, frameSize);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        decryptionInStream.close();

        assertArrayEquals(plaintextBytes, decryptedBytes);
    }

    @Test
    public void singleByteRead() throws IOException {
        final long inputSize = 10000; // 10KB
        final String inputFileName = sandboxPath_ + "plaintext_10KB.txt";
        final String encryptedFileName = new String(inputFileName + ".enc");
        final String decryptedFileName = new String(inputFileName + ".dec");

        TestIOUtils.generateFile(inputFileName, inputSize);

        final byte[] originalDigest = TestIOUtils.computeFileDigest(inputFileName);

        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final int frameSize = AwsCrypto.getDefaultFrameSize();
        encryptionClient_.setEncryptionFrameSize(frameSize);

        // encryption
        InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);
        OutputStream outStream = new FileOutputStream(encryptedFileName);

        // read 1 byte at a time to encrypt
        int readVal = 0;
        while (readVal >= 0) {
            readVal = encryptionInStream.read();
            if (readVal >= 0) {
                final byte readByte = (byte) (readVal & 0xff);
                outStream.write(readByte);
            }
        }
        outStream.close();
        encryptionInStream.close();

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        final InputStream decryptionInStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                inStream);
        outStream = new FileOutputStream(decryptedFileName);

        // read 1 byte at a time to decrypt
        readVal = 0;
        while (readVal >= 0) {
            readVal = decryptionInStream.read();
            if (readVal >= 0) {
                final byte readByte = (byte) (readVal & 0xff);
                outStream.write(readByte);
            }
        }
        outStream.close();
        decryptionInStream.close();

        final byte[] digestAfterDecryption = TestIOUtils.computeFileDigest(decryptedFileName);

        assertArrayEquals(originalDigest, digestAfterDecryption);
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullReadBuffer() throws BadCiphertextException, IOException {
        final long inputSize = 2048; // 2KB
        final String inputFileName = sandboxPath_ + "plaintext_2KB.txt";
        TestIOUtils.generateFile(inputFileName, inputSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);

        encryptionInStream.read(null);
    }

    @Test(expected = NullPointerException.class)
    public void nullReadBuffer2() throws BadCiphertextException, IOException {
        final long inputSize = 2048; // 2KB
        final String inputFileName = sandboxPath_ + "plaintext_2KB.txt";
        TestIOUtils.generateFile(inputFileName, inputSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);

        encryptionInStream.read(null, 0, 0);
    }

    @Test
    public void zeroReadLen() throws BadCiphertextException, IOException {
        final long inputSize = 2048; // 2KB
        final String inputFileName = sandboxPath_ + "plaintext_2KB.txt";
        TestIOUtils.generateFile(inputFileName, inputSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);

        final byte[] tempBytes = new byte[0];
        final int readLen = encryptionInStream.read(tempBytes);
        assertEquals(readLen, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeReadLen() throws BadCiphertextException, IOException {
        final int inputSize = 2048; // 2KB
        final String inputFileName = sandboxPath_ + "plaintext_2KB.txt";
        TestIOUtils.generateFile(inputFileName, inputSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);

        final byte[] tempBytes = new byte[inputSize];
        encryptionInStream.read(tempBytes, 0, -1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeReadOffset() throws BadCiphertextException, IOException {
        final int inputSize = 2048; // 2KB
        final String inputFileName = sandboxPath_ + "plaintext_2KB.txt";
        TestIOUtils.generateFile(inputFileName, inputSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);

        byte[] tempBytes = new byte[inputSize];
        encryptionInStream.read(tempBytes, -1, tempBytes.length);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void invalidReadOffset() throws BadCiphertextException, IOException {
        final int inputSize = 2048; // 2KB
        final String inputFileName = sandboxPath_ + "plaintext_2KB.txt";
        TestIOUtils.generateFile(inputFileName, inputSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);

        final byte[] tempBytes = new byte[inputSize];
        encryptionInStream.read(tempBytes, tempBytes.length + 1, tempBytes.length);
    }

    @Test
    public void noOpStream() throws IOException {
        final int inputSize = 2048; // 2KB
        final String inputFileName = sandboxPath_ + "plaintext_2KB.txt";
        TestIOUtils.generateFile(inputFileName, inputSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);

        encryptionInStream.close();
    }

    @Test
    public void decryptEmptyFile() throws IOException {
        final int inputSize = 0;
        final String inputFileName = sandboxPath_ + "encryptedtext_empty.txt";
        final String decryptedFileName = new String(inputFileName + ".dec");

        TestIOUtils.generateFile(inputFileName, inputSize);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final InputStream inStream = new FileInputStream(inputFileName);
        final InputStream decryptionInStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                inStream);
        final OutputStream outStream = new FileOutputStream(decryptedFileName);

        TestIOUtils.copyInStreamToOutStream(decryptionInStream, outStream);

        final File outFile = new File(decryptedFileName);
        assertEquals(0, outFile.length());
    }

    @Test
    public void checkEncContext() throws IOException {
        final int byteSize = 1;
        final String inputFileName = sandboxPath_ + "plaintext_" + byteSize + ".txt";
        final String encryptedFileName = new String(inputFileName + ".enc");
        final String decryptedFileName = new String(inputFileName + ".dec");

        TestIOUtils.generateFile(inputFileName, byteSize);

        final int frameSize = AwsCrypto.getDefaultFrameSize();
        encryptionClient_.setEncryptionFrameSize(frameSize);

        Map<String, String> setEncryptionContext = new HashMap<String, String>(1);
        setEncryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        // encryption
        InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                setEncryptionContext);
        OutputStream outStream = new FileOutputStream(encryptedFileName);

        TestIOUtils.copyInStreamToOutStream(encryptionInStream, outStream, frameSize);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        final CryptoInputStream<JceMasterKey> decryptionInStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                inStream);
        outStream = new FileOutputStream(decryptedFileName);

        TestIOUtils.copyInStreamToOutStream(decryptionInStream, outStream, frameSize);

        final CryptoResult<CryptoInputStream<JceMasterKey>, JceMasterKey> cryptoResult = decryptionInStream
                .getCryptoResult();
        Map<String, String> getEncryptionContext = cryptoResult.getEncryptionContext();

        // Since more values may have been added, we need to check to ensure that all
        // of setEncryptionContext is present, not that there is nothing else
        for (final Map.Entry<String, String> e : setEncryptionContext.entrySet()) {
            assertEquals(e.getValue(), getEncryptionContext.get(e.getKey()));
        }
    }

    @Test
    public void checkKeyId() throws IOException {
        final int byteSize = 1;
        final String inputFileName = sandboxPath_ + "plaintext_" + byteSize + ".txt";
        final String encryptedFileName = new String(inputFileName + ".enc");
        final String decryptedFileName = new String(inputFileName + ".dec");

        TestIOUtils.generateFile(inputFileName, byteSize);

        final int frameSize = AwsCrypto.getDefaultFrameSize();
        encryptionClient_.setEncryptionFrameSize(frameSize);

        Map<String, String> setEncryptionContext = new HashMap<String, String>(1);
        setEncryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        // encryption
        InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                setEncryptionContext);
        OutputStream outStream = new FileOutputStream(encryptedFileName);

        TestIOUtils.copyInStreamToOutStream(encryptionInStream, outStream, frameSize);

        inStream.close();
        outStream.close();

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        final CryptoInputStream<JceMasterKey> decryptionInStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                inStream);
        outStream = new FileOutputStream(decryptedFileName);

        TestIOUtils.copyInStreamToOutStream(decryptionInStream, outStream, frameSize);

        CryptoResult<CryptoInputStream<JceMasterKey>, JceMasterKey> cryptoResult = decryptionInStream.getCryptoResult();
        final String returnedKeyId = cryptoResult.getMasterKeys().get(0).getKeyId();

        assertEquals("mockKey", returnedKeyId);
    }

    @Test
    public void checkAvailable() throws IOException {
        final int byteSize = 128;
        final byte[] inBytes = TestIOUtils.generateRandomPlaintext(byteSize);
        final InputStream inStream = new ByteArrayInputStream(inBytes);

        final int frameSize = AwsCrypto.getDefaultFrameSize();
        encryptionClient_.setEncryptionFrameSize(frameSize);

        Map<String, String> setEncryptionContext = new HashMap<String, String>(1);
        setEncryptionContext.put("ENC", "Streaming Test");

        // encryption
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                setEncryptionContext);

        assertEquals(byteSize, encryptionInStream.available());
    }
}
