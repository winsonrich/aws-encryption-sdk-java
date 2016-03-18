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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoOutputStream;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import com.amazonaws.encryptionsdk.internal.TestIOUtils;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;

public class CryptoOutputStreamTest {
    private static final SecureRandom RND = new SecureRandom();
    private MasterKey<JceMasterKey> customerMasterKey;
    private AwsCrypto encryptionClient_;
    private Path sandbox_;
    private String sandboxPath_;

    @Rule
    public ExpectedException exception = ExpectedException.none();

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

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        encryptionClient_.setEncryptionFrameSize(frameSize);

        // encryption
        InputStream inStream = new FileInputStream(inputFileName);
        OutputStream outStream = new FileOutputStream(encryptedFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        TestIOUtils.copyInStreamToOutStream(inStream, encryptionOutStream);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        outStream = new FileOutputStream(decryptedFileName);
        final OutputStream decryptionOutStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                outStream);

        TestIOUtils.copyInStreamToOutStream(inStream, decryptionOutStream, readLen);

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
                    int[] readLenVals = { byteSize - 1, byteSize, byteSize + 1, byteSize * 2, 1000000 };

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
    public void singleByteWrite() throws IOException {
        final long inputSize = 10000; // 10KB
        final String inputFileName = sandboxPath_ + "plaintext_10KB.txt";
        final String encryptedFileName = new String(inputFileName + ".enc");
        final String decryptedFileName = new String(inputFileName + ".dec");

        TestIOUtils.generateFile(inputFileName, inputSize);

        final byte[] originalDigest = TestIOUtils.computeFileDigest(inputFileName);

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        // encryption
        InputStream inStream = new FileInputStream(inputFileName);
        OutputStream outStream = new FileOutputStream(encryptedFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        // write a single encrypted byte
        final byte[] writeBytes = new byte[2048];
        int read_len = 0;
        while (read_len >= 0) {
            read_len = inStream.read(writeBytes);
            if (read_len > 0) {
                for (int i = 0; i < read_len; i++) {
                    encryptionOutStream.write(writeBytes[i]);
                }
            }
        }
        inStream.close();
        encryptionOutStream.close();

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        outStream = new FileOutputStream(decryptedFileName);
        final OutputStream decryptionOutStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                outStream);

        // write a single decrypted byte
        read_len = 0;
        while (read_len >= 0) {
            read_len = inStream.read(writeBytes);
            if (read_len > 0) {
                for (int i = 0; i < read_len; i++) {
                    decryptionOutStream.write(writeBytes[i]);
                }
            }
        }
        inStream.close();
        decryptionOutStream.close();

        final byte[] digestAfterDecryption = TestIOUtils.computeFileDigest(decryptedFileName);

        assertArrayEquals(originalDigest, digestAfterDecryption);
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
        OutputStream outStream = new FileOutputStream(encryptedFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream);

        TestIOUtils.copyInStreamToOutStream(inStream, encryptionOutStream);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        outStream = new FileOutputStream(decryptedFileName);
        final OutputStream decryptionOutStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                outStream);

        TestIOUtils.copyInStreamToOutStream(inStream, decryptionOutStream);

        final byte[] digestAfterDecryption = TestIOUtils.computeFileDigest(decryptedFileName);

        assertArrayEquals(originalDigest, digestAfterDecryption);
    }

    @Test
    public void encryptAPIComptability() throws IOException {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final String inputFileName = sandboxPath_ + "plaintext_1MB.txt";
        final String decryptedFileName = new String(inputFileName + ".dec");

        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Test with %s" + inputFileName);

        encryptionClient_.setEncryptionFrameSize(AwsCrypto.getDefaultFrameSize());

        // encryption
        final CryptoResult<byte[], JceMasterKey> cipherText = encryptionClient_.encryptData(
                customerMasterKey,
                plaintextBytes,
                encryptionContext);

        // decryption
        final FileOutputStream outStream = new FileOutputStream(decryptedFileName);
        final OutputStream decryptionOutStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                outStream);

        decryptionOutStream.write(cipherText.getResult());
        decryptionOutStream.close();

        final FileInputStream inStream = new FileInputStream(decryptedFileName);
        final byte[] decryptedBytes = new byte[ptSize];
        int readLen = 0;
        while (readLen >= 0) {
            try {
                readLen = inStream.read(decryptedBytes);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        inStream.close();

        assertArrayEquals(plaintextBytes, decryptedBytes);
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
        outStream = new FileOutputStream(encryptedFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        TestIOUtils.copyInStreamToOutStream(inStream, encryptionOutStream);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        final int encryptedBytesLen = (int) Files.size(Paths.get(encryptedFileName));
        byte[] encryptedBytes = new byte[encryptedBytesLen];

        int readLen = 0;
        int totalRead = 0;
        while (readLen >= 0) {
            try {
                readLen = inStream.read(encryptedBytes);
                totalRead += Math.max(readLen, 0);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        inStream.close();

        encryptedBytes = Utils.truncate(encryptedBytes, totalRead);
        final CryptoResult<byte[], JceMasterKey> decryptedText = encryptionClient_.decryptData(customerMasterKey,
                encryptedBytes);

        assertArrayEquals(plaintextBytes, decryptedText.getResult());
    }

    @Test
    public void inputStreamComptability() throws IOException {
        final int ptSize = 1000000; // 1MB
        final byte[] plaintextBytes = TestIOUtils.generateRandomPlaintext(ptSize);

        final String inputFileName = sandboxPath_ + "plaintext_1MB.txt";
        final String encryptedFileName = new String(inputFileName + ".enc");
        final String decryptedFileName = new String(inputFileName + ".dec");

        OutputStream outStream = new FileOutputStream(inputFileName);
        outStream.write(plaintextBytes);
        outStream.close();

        Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + inputFileName);

        final int frameSize = AwsCrypto.getDefaultFrameSize();
        encryptionClient_.setEncryptionFrameSize(frameSize);

        // encryption
        outStream = new FileOutputStream(encryptedFileName);
        InputStream inStream = new FileInputStream(inputFileName);
        final InputStream encryptionInStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                inStream,
                encryptionContext);

        TestIOUtils.copyInStreamToOutStream(encryptionInStream, outStream);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        outStream = new FileOutputStream(decryptedFileName);
        final OutputStream decryptionOutStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                outStream);

        TestIOUtils.copyInStreamToOutStream(inStream, decryptionOutStream);

        inStream = new FileInputStream(decryptedFileName);

        final byte[] decryptedBytes = new byte[ptSize];
        int readLen = 0;
        while (readLen >= 0) {
            try {
                readLen = inStream.read(decryptedBytes);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        inStream.close();

        assertArrayEquals(plaintextBytes, decryptedBytes);
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullWrite() throws IOException {
        final String outputFileName = sandboxPath_ + "dummy.out";

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + outputFileName);

        final OutputStream outStream = new FileOutputStream(outputFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        encryptionOutStream.write(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullWrite2() throws BadCiphertextException, IOException {
        final String outputFileName = sandboxPath_ + "dummy.out";

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + outputFileName);

        final OutputStream outStream = new FileOutputStream(outputFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        encryptionOutStream.write(null, 0, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeWriteLen() throws BadCiphertextException, IOException {
        final String outputFileName = sandboxPath_ + "dummy.out";

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + outputFileName);

        final OutputStream outStream = new FileOutputStream(outputFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        final byte[] writeBytes = new byte[0];
        encryptionOutStream.write(writeBytes, 0, -1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeWriteOffset() throws BadCiphertextException, IOException {
        final String outputFileName = sandboxPath_ + "dummy.out";

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + outputFileName);

        final OutputStream outStream = new FileOutputStream(outputFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        final byte[] writeBytes = new byte[2048];
        encryptionOutStream.write(writeBytes, -1, writeBytes.length);
    }

    @Test
    public void checkInvalidValues() throws IOException {
        // test for the two formats - single-block and frame.
        final int[] frameSizeToTest = { 0, AwsCrypto.getDefaultFrameSize() };

        // iterate over frame size to test
        for (int i = 0; i < frameSizeToTest.length; i++) {
            final int frameSize = frameSizeToTest[i];
            invalidWriteLen(frameSize);
            invalidWriteOffset(frameSize);
            noOpStream(frameSize);
        }
    }

    private void invalidWriteLen(final int frameSize) throws BadCiphertextException, IOException {
        final String outputFileName = sandboxPath_ + "dummy.out";

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + outputFileName);

        encryptionClient_.setEncryptionFrameSize(frameSize);

        final OutputStream outStream = new FileOutputStream(outputFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        final byte[] writeBytes = new byte[2048];

        exception.expect(IndexOutOfBoundsException.class);
        encryptionOutStream.write(writeBytes, 0, 2 * writeBytes.length);
    }

    private void invalidWriteOffset(final int frameSize) throws BadCiphertextException, IOException {
        final String outputFileName = sandboxPath_ + "dummy.out";

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + outputFileName);

        encryptionClient_.setEncryptionFrameSize(frameSize);

        final OutputStream outStream = new FileOutputStream(outputFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        final byte[] writeBytes = new byte[2048];

        exception.expect(IndexOutOfBoundsException.class);
        encryptionOutStream.write(writeBytes, writeBytes.length + 1, writeBytes.length);
    }

    private void noOpStream(final int frameSize) throws IOException {
        final String outFileName = sandboxPath_ + "no-op.txt";

        final Map<String, String> encryptionContext = new HashMap<String, String>(1);
        encryptionContext.put("ENC", "Streaming Test with %s" + outFileName);

        final OutputStream outStream = new FileOutputStream(outFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                encryptionContext);

        encryptionOutStream.close();

        final File outFile = new File(outFileName);
        assertEquals(0, outFile.length());
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
        final OutputStream outStream = new FileOutputStream(decryptedFileName);
        final OutputStream decryptionOutStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                outStream);

        TestIOUtils.copyInStreamToOutStream(inStream, decryptionOutStream);
        inStream.close();
        decryptionOutStream.close();

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
        OutputStream outStream = new FileOutputStream(encryptedFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                setEncryptionContext);

        TestIOUtils.copyInStreamToOutStream(inStream, encryptionOutStream);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        outStream = new FileOutputStream(decryptedFileName);
        final CryptoOutputStream<JceMasterKey> decryptionOutStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                outStream);

        TestIOUtils.copyInStreamToOutStream(inStream, decryptionOutStream);

        Map<String, String> getEncryptionContext = decryptionOutStream.getCryptoResult().getEncryptionContext();

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
        OutputStream outStream = new FileOutputStream(encryptedFileName);
        final OutputStream encryptionOutStream = encryptionClient_.createEncryptingStream(
                customerMasterKey,
                outStream,
                setEncryptionContext);

        TestIOUtils.copyInStreamToOutStream(inStream, encryptionOutStream);

        // decryption
        inStream = new FileInputStream(encryptedFileName);
        outStream = new FileOutputStream(decryptedFileName);
        final CryptoOutputStream<JceMasterKey> decryptionOutStream = encryptionClient_.createDecryptingStream(
                customerMasterKey,
                outStream);

        TestIOUtils.copyInStreamToOutStream(inStream, decryptionOutStream);

        final String returnedKeyId = decryptionOutStream.getCryptoResult().getMasterKeys().get(0).getKeyId();

        assertEquals("mockKey", returnedKeyId);
    }
}
