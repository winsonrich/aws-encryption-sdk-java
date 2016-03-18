# AWS Encryption SDK for Java

The AWS Encryption SDK enables secure client-side encryption by using cryptography best practices to protect your data and the encryption keys used to protect that data. Each data object is protected with a unique data encryption key (DEK), and the DEK is protected with a key encryption key (KEK) called a *master key*. The encrypted DEK is combined with the encrypted data into a single encrypted message, so you don't need to keep track of the DEKs for your data. The SDK supports master keys in the [AWS Key Management Service](https://aws.amazon.com/kms/) (AWS KMS), and it also provides APIs to define and use other master key providers. The SDK provides methods for encrypting and decrypting strings, byte arrays, and byte streams. For details, see the [example code][examples].

For more details about the design and architecture of the SDK, see the [official documentation](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/).

## Getting Started

### Required Prerequisites
To use this SDK you must have:

* **A Java development environment**
If you do not have one, go to [Java SE Downloads](https://www.oracle.com/technetwork/java/javase/downloads/index.html) and then download and install the Java SE Development Kit (JDK).

* **Bouncy Castle**
Bouncy Castle provides a cryptography API for Java. If you do not have Bouncy Castle, go to https://bouncycastle.org/latest_releases.html and then download the provider file that corresponds to your JDK.

### Optional Prerequisites

You don't need an Amazon Web Services (AWS) account to use this SDK, but some of the [example code][examples] requires an AWS account, a customer master key (CMK) in AWS KMS, and the AWS SDK for Java.

* **To sign up for AWS**, go to [Sign In or Create an AWS Account](https://portal.aws.amazon.com/gp/aws/developer/registration/index.html) and choose **I am a new user.** Follow the instructions to sign up and create an AWS account.

* **To create a CMK in AWS KMS**, go to [Creating Keys](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html) in the KMS documentation and then follow the instructions on that page.

* **To download and install the AWS SDK for Java**, go to [Installing the AWS SDK for Java](https://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/java-dg-install-sdk.html) in the *AWS SDK for Java Developer Guide* and then follow the instructions on that page.

### Download the SDK

### Get Started

The following code sample demonstrates how to get started:

1. Instantiate the SDK
2. Define the master key provider
3. Encrypt and decrypt data

```java
// This sample code encrypts and then decrypts a string using a KMS master key.
// You provide the KMS key ARN and plaintext string as arguments.
package com.amazonaws.crypto.examples;

import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

public class StringExample {
    private static String keyArn;
    private static String data;

    public static void main(final String[] args) {
        keyArn = args[0];
        data = args[1];

        // Instantiate the SDK
        final AwsCrypto crypto = new AwsCrypto();

        // Set up the master key provider
        final KmsMasterKeyProvider prov = new KmsMasterKeyProvider(keyArn);

        // Encrypt the data
        //
        // NOTE: Encrypted data should have associated encryption context
        // to protect integrity. For this example, just use a placeholder
        // value. For more information about encryption context, see
        // https://amzn.to/1nSbe9X (blogs.aws.amazon.com)
        final Map<String, String> context = Collections.singletonMap("Example", "String");

        final String ciphertext = crypto.encryptString(prov, data, context).getResult();
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the data
        final CryptoResult<String, KmsMasterKey> decryptResult = crypto.decryptString(prov, ciphertext);
        // Check the encryption context (and ideally the master key) to
        // ensure this is the expected ciphertext
        if (!decryptResult.getMasterKeyIds().get(0).equals(keyArn)) {
            throw new IllegalStateException("Wrong key id!");
        }

        // The SDK may add information to the encryption context, so check to
        // ensure all of the values are present
        for (final Map.Entry<String, String> e : context.entrySet()) {
            if (!e.getValue().equals(decryptResult.getEncryptionContext().get(e.getKey()))) {
                throw new IllegalStateException("Wrong Encryption Context!");
            }
        }

        // The data is correct, so output it.
        System.out.println("Decrypted: " + decryptResult.getResult());
    }
}
```

For more examples, look in the [examples directory][examples].

## FAQ

See the [Frequently Asked Questions](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/faq.html) page in the official documentation.

[examples]: examples/com/amazonaws/crypto/examples/
