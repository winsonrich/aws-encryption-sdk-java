/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazonaws.crypto.examples;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoOutputStream;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.amazonaws.util.IOUtils;

/**
 * <p>
 * Encrypts a file using both KMS and an asymmetric key pair.
 *
 * <p>
 * Arguments:
 * <ol>
 * <li>Key ARN: To find the Amazon Resource Name of your KMS customer master key (CMK), 
 *     see 'Viewing Keys' at http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html
 * <li>File Name
 * </ol>
 *
 * AWS Key Management Service (KMS) is highly available. However, some organizations want to decrypt
 * their data offline and independent of KMS. This sample demonstrates one way to do this.
 * 
 * This program generates an "escrowed" RSA key pair. It stores the private key in a secure offline 
 * location, such as an offline HSM, and distributes the public key to their developers. It also 
 * creates a KMS customer master key (CMK). The organization encrypts their data with both the 
 * KMS CMK and the public key, so that either key alone could decrypt it. 
 *
 * The team usually uses the KMS CMK for decryption. However, the organization can, at any time
 * use the private escrowed RSA key to decrypt the ciphertext independent of KMS. 
 */
public class EscrowedEncryptExample {
    private static PublicKey publicEscrowKey;
    private static PrivateKey privateEscrowKey;

    public static void main(final String[] args) throws Exception {
        // In practice, the organization would distribute the public key.
        // For this demo, we generate a new random key for each operation.
        generateEscrowKeyPair();

        final String kmsArn = args[0];
        final String fileName = args[1];

        standardEncrypt(kmsArn, fileName);
        standardDecrypt(kmsArn, fileName);

        escrowDecrypt(fileName);
    }

    private static void standardEncrypt(final String kmsArn, final String fileName) throws Exception {
        // Standard practice: encrypt with the KMS CMK and the escrowed public key
        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a KMS master key provider
        final KmsMasterKeyProvider kms = new KmsMasterKeyProvider(kmsArn);
        
		// 3. Instantiate a JCE master key provider
		// Because the standard user does not have access to the private 
        // escrow key, they pass in "null" for the private key parameter.
        final JceMasterKey escrowPub = JceMasterKey.getInstance(publicEscrowKey, null, "Escrow", "Escrow",
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

        // 4. Combine the providers into a single master key provider
        final MasterKeyProvider<?> provider = MultipleProviderFactory.buildMultiProvider(kms, escrowPub);

        // 5. Encrypt the file
        // To simplify the code, we omit the encryption context. Production code should always 
        // use an encryption context. For an example, see the other SDK samples.
        final FileInputStream in = new FileInputStream(fileName);
        final FileOutputStream out = new FileOutputStream(fileName + ".encrypted");
        final CryptoOutputStream<?> encryptingStream = crypto.createEncryptingStream(provider, out);

        IOUtils.copy(in, encryptingStream);
        in.close();
        encryptingStream.close();
    }

    private static void standardDecrypt(final String kmsArn, final String fileName) throws Exception {
        // Standard practice: enncrypt with the KMS CMK and the escrow public key

        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a KMS master key provider
        final KmsMasterKeyProvider kms = new KmsMasterKeyProvider(kmsArn);
        
		// 3. Instantiate a JCE master key provider
        // Because the standard user does not have access to the private 
        // escrow key, they pass in "null" for the private key parameter.
        final JceMasterKey escrowPub = JceMasterKey.getInstance(publicEscrowKey, null, "Escrow", "Escrow",
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

        // 4. Combine the providers into a single master key provider
        final MasterKeyProvider<?> provider = MultipleProviderFactory.buildMultiProvider(kms, escrowPub);

        // 5. Decrypt the file
        // To simplify the code, we omit the encryption context. Production code should always 
        // use an encryption context. For an example, see the other SDK samples.
        final FileInputStream in = new FileInputStream(fileName + ".encrypted");
        final FileOutputStream out = new FileOutputStream(fileName + ".decrypted");
        final CryptoOutputStream<?> decryptingStream = crypto.createDecryptingStream(provider, out);
        IOUtils.copy(in, decryptingStream);
        in.close();
        decryptingStream.close();
    }

    private static void escrowDecrypt(final String fileName) throws Exception {
        // The organization can decrypt the stream using only the private escrow key. 
		// This method does not call KMS.

        // 1. Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // 2. Instantiate a JCE master key provider
        // This method call uses the escrowed private key 
        final JceMasterKey escrowPriv = JceMasterKey.getInstance(publicEscrowKey, privateEscrowKey, "Escrow", "Escrow",
                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding");

        // 3. Decrypt the file
        // To simplify the code, we omit the encryption context. Production code should always 
        // use an encryption context. For an example, see the other SDK samples.
        final FileInputStream in = new FileInputStream(fileName + ".encrypted");
        final FileOutputStream out = new FileOutputStream(fileName + ".deescrowed");
        final CryptoOutputStream<?> decryptingStream = crypto.createDecryptingStream(escrowPriv, out);
        IOUtils.copy(in, decryptingStream);
        in.close();
        decryptingStream.close();

    }

    private static void generateEscrowKeyPair() throws GeneralSecurityException {
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(4096); // Escrow keys should be very strong
        final KeyPair keyPair = kg.generateKeyPair();
        publicEscrowKey = keyPair.getPublic();
        privateEscrowKey = keyPair.getPrivate();

    }
}
