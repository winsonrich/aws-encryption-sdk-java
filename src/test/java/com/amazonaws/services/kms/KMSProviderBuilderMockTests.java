package com.amazonaws.services.kms;

import static com.amazonaws.regions.Region.getRegion;
import static com.amazonaws.regions.Regions.fromName;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider.RegionalClientSupplier;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;

public class KMSProviderBuilderMockTests {
    @Test
    public void testGrantTokenPassthrough() throws Exception {
        MockKMSClient client = spy(new MockKMSClient());

        RegionalClientSupplier supplier = mock(RegionalClientSupplier.class);
        when(supplier.getClient(any())).thenReturn(client);

        String key1 = client.createKey().getKeyMetadata().getArn();
        String key2 = client.createKey().getKeyMetadata().getArn();

        KmsMasterKeyProvider mkp = KmsMasterKeyProvider.builder()
                                                       .withDefaultRegion("us-west-2")
                                                       .withCustomClientFactory(supplier)
                                                       .withKeysForEncryption(key1, key2)
                                                       .withGrantTokens(singletonList("foo"))
                                                       .build();

        byte[] ciphertext = new AwsCrypto().encryptData(mkp, new byte[0]).getResult();

        ArgumentCaptor<GenerateDataKeyRequest> gdkr = ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
        verify(client, times(1)).generateDataKey(gdkr.capture());

        assertEquals(key1, gdkr.getValue().getKeyId());
        assertEquals(1, gdkr.getValue().getGrantTokens().size());
        assertEquals("foo", gdkr.getValue().getGrantTokens().get(0));

        ArgumentCaptor<EncryptRequest> er = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(client, times(1)).encrypt(er.capture());

        assertEquals(key2, er.getValue().getKeyId());
        assertEquals(1, er.getValue().getGrantTokens().size());
        assertEquals("foo", er.getValue().getGrantTokens().get(0));

        new AwsCrypto().decryptData(mkp, ciphertext);

        ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
        verify(client, times(1)).decrypt(decrypt.capture());

        assertEquals(1, decrypt.getValue().getGrantTokens().size());
        assertEquals("foo", decrypt.getValue().getGrantTokens().get(0));

        verify(supplier, atLeastOnce()).getClient("us-west-2");
        verifyNoMoreInteractions(supplier);
    }

    @Test
    public void testLegacyGrantTokenPassthrough() throws Exception {
        MockKMSClient client = spy(new MockKMSClient());

        String key1 = client.createKey().getKeyMetadata().getArn();

        KmsMasterKeyProvider mkp = new KmsMasterKeyProvider(client, getRegion(fromName("us-west-2")), Collections.singletonList(key1));

        mkp.addGrantToken("x");
        mkp.setGrantTokens(new ArrayList<>(Arrays.asList("y")));
        mkp.setGrantTokens(new ArrayList<>(Arrays.asList("a", "b")));
        mkp.addGrantToken("c");

        byte[] ciphertext = new AwsCrypto().encryptData(mkp, new byte[0]).getResult();

        ArgumentCaptor<GenerateDataKeyRequest> gdkr = ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
        verify(client, times(1)).generateDataKey(gdkr.capture());

        List<String> grantTokens = gdkr.getValue().getGrantTokens();
        assertTrue(grantTokens.contains("a"));
        assertTrue(grantTokens.contains("b"));
        assertTrue(grantTokens.contains("c"));
        assertFalse(grantTokens.contains("x"));
        assertFalse(grantTokens.contains("z"));
    }
}
