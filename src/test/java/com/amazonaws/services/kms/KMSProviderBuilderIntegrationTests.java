package com.amazonaws.services.kms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.Assume;
import org.junit.Test;

import com.amazonaws.AbortedException;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.exception.CannotUnwrapDataKeyException;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.handlers.RequestHandler2;
import com.amazonaws.http.exception.HttpRequestTimeoutException;
import com.amazonaws.regions.DefaultAwsRegionProviderChain;

public class KMSProviderBuilderIntegrationTests {
    public String[] keyIds = new String[] {
            "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f",
            "arn:aws:kms:eu-central-1:658956600833:key/75414c93-5285-4b57-99c9-30c1cf0a22c2"
    };

    @Test
    public void whenConstructedWithoutArguments_canUseMultipleRegions() throws Exception {
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder().build();

        for (String key : keyIds) {
            byte[] ciphertext =
                    new AwsCrypto().encryptData(
                            KmsMasterKeyProvider.builder()
                                .withKeysForEncryption(key)
                                .build(),
                            new byte[1]
                    ).getResult();

            new AwsCrypto().decryptData(mkp, ciphertext);
        }
    }

    @SuppressWarnings("deprecation") @Test(expected = CannotUnwrapDataKeyException.class)
    public void whenLegacyConstructorsUsed_multiRegionDecryptIsNotSupported() throws Exception {
        KmsMasterKeyProvider mkp = new KmsMasterKeyProvider();

        for (String key : keyIds) {
            byte[] ciphertext =
                    new AwsCrypto().encryptData(
                            KmsMasterKeyProvider.builder()
                                                .withKeysForEncryption(key)
                                                .build(),
                            new byte[1]
                    ).getResult();

            new AwsCrypto().decryptData(mkp, ciphertext);
        }
    }

    @Test
    public void whenHandlerConfigured_handlerIsInvoked() throws Exception {
        RequestHandler2 handler = spy(new RequestHandler2() {});
        KmsMasterKeyProvider mkp =
                KmsMasterKeyProvider.builder()
                                    .withClientBuilder(
                                            AWSKMSClientBuilder.standard()
                                                .withRequestHandlers(handler)
                                    )
                                    .withKeysForEncryption(keyIds[0])
                                    .build();

        new AwsCrypto().encryptData(mkp, new byte[1]);

        verify(handler).beforeRequest(any());
    }

    @Test
    public void whenShortTimeoutSet_timesOut() throws Exception {
        // By setting a timeout of 1ms, it's not physically possible to complete both the us-west-2 and eu-central-1
        // requests due to speed of light limits.
        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
                                                       .withClientBuilder(
                                                               AWSKMSClientBuilder.standard()
                                                                .withClientConfiguration(
                                                                        new ClientConfiguration()
                                                                            .withRequestTimeout(1)
                                                                )
                                                       )
                                                       .withKeysForEncryption(Arrays.asList(keyIds))
                                                       .build();

        try {
            new AwsCrypto().encryptData(mkp, new byte[1]);
            fail("Expected exception");
        } catch (Exception e) {
            if (e instanceof AbortedException) {
                // ok - one manifestation of a timeout
            } else if (e.getCause() instanceof HttpRequestTimeoutException) {
                // ok - another kind of timeout
            } else {
                throw e;
            }
        }
    }

    @Test
    public void whenCustomCredentialsSet_theyAreUsed() throws Exception {
        AWSCredentialsProvider customProvider = spy(new DefaultAWSCredentialsProviderChain());

        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
                                                       .withCredentials(customProvider)
                                                       .withKeysForEncryption(keyIds[0])
                                                       .build();

        new AwsCrypto().encryptData(mkp, new byte[1]);

        verify(customProvider, atLeastOnce()).getCredentials();

        AWSCredentials customCredentials = spy(customProvider.getCredentials());

        mkp = KmsMasterKeyProvider.builder()
                                                       .withCredentials(customCredentials)
                                                       .withKeysForEncryption(keyIds[0])
                                                       .build();

        new AwsCrypto().encryptData(mkp, new byte[1]);

        verify(customCredentials, atLeastOnce()).getAWSSecretKey();
    }

    @Test(expected = IllegalArgumentException.class)
    public void whenBogusEndpointIsSet_constructionFails() throws Exception {
        KmsMasterKeyProvider.builder()
                            .withClientBuilder(
                                    AWSKMSClientBuilder.standard()
                                                       .withEndpointConfiguration(
                                                               new AwsClientBuilder.EndpointConfiguration(
                                                                       "https://this.does.not.exist.example.com",
                                                                       "bad-region")
                                                       )
                            );
    }

    @Test
    public void whenDefaultRegionSet_itIsUsedForBareKeyIds() throws Exception {
        // TODO: Need to set up a role to assume as bare key IDs are relative to the caller account
    }

    @Test
    public void whenDefaultRegionIsNotSet_providerChainDefaultIsUsed() throws Exception {
        assertDefaultRegionConsistency();

        String oldRegion = System.getProperty("aws.region");
        Assume.assumeFalse("Can't change env variables from within Java", System.getenv("AWS_REGION") != null);

        try {
            System.setProperty("aws.region", "eu-central-1");
            assertEquals("eu-central-1", getInitialDefaultRegion());

            System.setProperty("aws.region", "us-west-2");
            assertEquals("us-west-2", getInitialDefaultRegion());

        } finally {
            if (oldRegion != null) {
                System.setProperty("aws.region", oldRegion);
            } else {
                System.clearProperty("aws.region");
            }
        }
    }

    private void assertDefaultRegionConsistency() throws Exception {
        String initialDefault = getInitialDefaultRegion();

        assertEquals(
                new DefaultAwsRegionProviderChain().getRegion(),
                initialDefault
        );
    }

    private String getInitialDefaultRegion() throws NoSuchFieldException, IllegalAccessException {
        KmsMasterKeyProvider.Builder builder = KmsMasterKeyProvider.builder();

        Field f = KmsMasterKeyProvider.Builder.class.getDeclaredField("defaultRegion_");
        f.setAccessible(true);

        return (String) f.get(builder);
    }
}
