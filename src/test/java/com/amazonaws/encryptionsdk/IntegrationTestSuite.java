package com.amazonaws.encryptionsdk;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import com.amazonaws.services.kms.KMSProviderBuilderIntegrationTests;
import com.amazonaws.services.kms.XCompatKmsDecryptTest;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        XCompatKmsDecryptTest.class,
        KMSProviderBuilderIntegrationTests.class
})
public class IntegrationTestSuite {
}
