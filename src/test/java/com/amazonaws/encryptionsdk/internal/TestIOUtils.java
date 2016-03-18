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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.lang3.RandomStringUtils;

public class TestIOUtils {
    private static final SecureRandom rng_ = new SecureRandom();

    public static byte[] generateRandomPlaintext(final int size) {
        return RandomBytesGenerator.generate(size);
    }

    public static String generateRandomString(final int size) {
        return RandomStringUtils.random(size);
    }

    public static byte[] computeFileDigest(final String fileName) throws IOException {
        try {
            final FileInputStream fis = new FileInputStream(fileName);
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            final DigestInputStream dis = new DigestInputStream(fis, md);

            final int readLen = 128;
            final byte[] readBytes = new byte[readLen];
            while (dis.read(readBytes) != -1) {
            }
            dis.close();

            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            // shouldn't get here since we hardcode the algorithm.
        }

        return null;
    }

    public static byte[] getSha256Hash(final byte[] input) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // should never get here.
        }
        return md.digest(input);
    }

    public static void generateFile(final String fileName, final long fileSize) throws IOException {
        final FileOutputStream fs = new FileOutputStream(fileName);
        final byte[] fileBytes = new byte[(int) fileSize];
        rng_.nextBytes(fileBytes);
        fs.write(fileBytes);
        fs.close();
    }

    public static void copyInStreamToOutStream(final InputStream inStream, final OutputStream outStream,
            final int readLen) throws IOException {
        final byte[] readBuffer = new byte[readLen];
        int actualRead = 0;
        while (actualRead >= 0) {
            outStream.write(readBuffer, 0, actualRead);
            actualRead = inStream.read(readBuffer);
        }
        inStream.close();
        outStream.close();
    }

    public static void deleteDir(final File filePath) {
        if (filePath.exists()) {
            File[] files = filePath.listFiles();
            for (int i = 0; i < files.length; i++) {
                if (files[i].isFile()) {
                    files[i].delete();
                } else {
                    deleteDir(files[i]);
                }
            }
        }

        filePath.delete();
    }

    public static void copyInStreamToOutStream(final InputStream inStream, final OutputStream outStream)
            throws IOException {
        final int readLen = 1024; // 1KB
        copyInStreamToOutStream(inStream, outStream, readLen);
    }
}
