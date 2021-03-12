import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.DefaultDapsDriver;
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.DefaultDapsDriverConfig;
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.SecurityProfile;
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.SecurityRequirements;
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.DapsDriver;
import org.junit.Ignore;
import org.junit.Test;

import java.nio.file.Paths;

import static org.junit.Assert.*;

@Ignore("Some test rely on external server resources and are somewhat unreliable right now.")
public class DapsDriverTest {

    @Test
    public void testValidToken() {

        SecurityRequirements requirements = new SecurityRequirements.Builder()
                .setRequiredSecurityLevel(SecurityProfile.TRUSTED)
                .build();

        SecurityRequirements requirements2 = new SecurityRequirements.Builder()
                .setRequiredSecurityLevel(SecurityProfile.BASE)
                .build();

        DefaultDapsDriverConfig config =
                new DefaultDapsDriverConfig.Builder()
                        .setKeyStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/aisecconnector1-keystore.p12").getPath()))
                        .setTrustStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/client-truststore_new.p12").getPath()))
                        .setKeyStorePassword("password".toCharArray())
                        .setTrustStorePassword("password".toCharArray())
                        .setKeyAlias("1")
                        .setKeyPassword("password".toCharArray())
                        .setDapsUrl("https://daps.aisec.fraunhofer.de")
                        .build();

        DefaultDapsDriver dapsDriver = new DefaultDapsDriver(config);
        String token = new String(dapsDriver.getToken());
        assertNotEquals(token, "INVALID_TOKEN");


        assertTrue(dapsDriver.verifyTokenSecurityAttributes(token.getBytes(), requirements, null) >= 0);
        assertFalse(dapsDriver.verifyTokenSecurityAttributes(token.getBytes(), requirements2, null) >= 0);
    }

    /****
     @Test public void testInvalidClient() {
     DefaultDapsDriverConfig config =
     new DefaultDapsDriverConfig.Builder()
     .setKeyStorePath(DapsDriverTest.class.getClassLoader().
     getResource("ssl/aisecconnector1-keystore.p12").getPath())
     .setTrustStorePath(DapsDriverTest.class.getClassLoader().
     getResource("ssl/client-truststore_new.p12").getPath())
     .setKeyStorePassword("password")
     .setTrustStorePassword("password")
     .setKeyAlias("1")
     .setDapsUrl("https://daps.aisec.fraunhofer.de")
     .build();

     DapsDriver dapsDriver = new DefaultDapsDriver(config);
     String token = new String(dapsDriver.getToken());
     assertEquals(token, "INVALID_TOKEN");
     }
     **/

    @Test
    public void testInvalidUrlNonSecure() {
        DefaultDapsDriverConfig config =
                new DefaultDapsDriverConfig.Builder()
                        .setKeyStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/aisecconnector1-keystore.p12").getPath()))
                        .setTrustStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/client-truststore_new.p12").getPath()))
                        .setKeyStorePassword("password".toCharArray())
                        .setTrustStorePassword("password".toCharArray())
                        .setKeyAlias("1")
                        .setKeyPassword("password".toCharArray())
                        .setDapsUrl("https://daps.aisec.fraunhofer.de")
                        .build();

        DapsDriver dapsDriver = new DefaultDapsDriver(config);
        String token = new String(dapsDriver.getToken());
        assertEquals(token, "INVALID_TOKEN");
    }

    @Test
    public void testInvalidUrl404() {
        DefaultDapsDriverConfig config =
                new DefaultDapsDriverConfig.Builder()
                        .setKeyStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/aisecconnector1-keystore.p12").getPath()))
                        .setTrustStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/client-truststore_new.p12").getPath()))
                        .setKeyStorePassword("password".toCharArray())
                        .setTrustStorePassword("password".toCharArray())
                        .setKeyAlias("1")
                        .setKeyPassword("password".toCharArray())
                        .setDapsUrl("https://daps.aisec.fraunhofer.de")
                        .build();

        DapsDriver dapsDriver = new DefaultDapsDriver(config);
        String token = new String(dapsDriver.getToken());
        assertEquals(token, "INVALID_TOKEN");
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidPassword1() {
        DefaultDapsDriverConfig config =
                new DefaultDapsDriverConfig.Builder()
                        .setKeyStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/aisecconnector1-keystore.p12").getPath()))
                        .setTrustStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/client-truststore_new.p12").getPath()))
                        .setKeyStorePassword("INVALID_PASSWORD".toCharArray())
                        .setTrustStorePassword("password".toCharArray())
                        .setKeyAlias("1")
                        .setKeyPassword("password".toCharArray())
                        .setDapsUrl("https://daps.aisec.fraunhofer.de")
                        .build();

        new DefaultDapsDriver(config);
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidPassword2() {
        DefaultDapsDriverConfig config =
                new DefaultDapsDriverConfig.Builder()
                        .setKeyStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/aisecconnector1-keystore.p12").getPath()))
                        .setTrustStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/client-truststore_new.p12").getPath()))
                        .setKeyStorePassword("password".toCharArray())
                        .setTrustStorePassword("INVALID_PASSWORD".toCharArray())
                        .setKeyAlias("1")
                        .setKeyPassword("password".toCharArray())
                        .setDapsUrl("https://daps.aisec.fraunhofer.de")
                        .build();

        new DefaultDapsDriver(config);
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidKeyAlias() {
        DefaultDapsDriverConfig config =
                new DefaultDapsDriverConfig.Builder()
                        .setKeyStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/aisecconnector1-keystore.p12").getPath()))
                        .setTrustStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/client-truststore_new.p12").getPath()))
                        .setKeyStorePassword("password".toCharArray())
                        .setTrustStorePassword("password".toCharArray())
                        .setKeyAlias("INVALID_ALIAS")
                        .setKeyPassword("password".toCharArray())
                        .setDapsUrl("https://daps.aisec.fraunhofer.de")
                        .build();

        new DefaultDapsDriver(config);
    }

    @Test
    public void testInvalidAuditLogging() {

        SecurityRequirements requirements = new SecurityRequirements.Builder()
                .setRequiredSecurityLevel(SecurityProfile.TRUSTED_PLUS)
                .build();

        DefaultDapsDriverConfig config =
                new DefaultDapsDriverConfig.Builder()
                        .setKeyStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/aisecconnector1-keystore.p12").getPath()))
                        .setTrustStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/client-truststore_new.p12").getPath()))
                        .setKeyStorePassword("password".toCharArray())
                        .setTrustStorePassword("password".toCharArray())
                        .setKeyAlias("1")
                        .setKeyPassword("password".toCharArray())
                        .setDapsUrl("https://daps.aisec.fraunhofer.de")
                        .setSecurityRequirements(requirements)
                        .build();

        DapsDriver dapsDriver = new DefaultDapsDriver(config);
        String token = new String(dapsDriver.getToken());
        assertNotEquals(token, "INVALID_TOKEN");

        assertTrue(dapsDriver.verifyToken(token.getBytes(), null) < 0);
    }

    public static void main(String[] args) {

        SecurityRequirements requirements = new SecurityRequirements.Builder()
                .setRequiredSecurityLevel(SecurityProfile.TRUSTED)
                .build();

        //get token
        DefaultDapsDriverConfig config =
                new DefaultDapsDriverConfig.Builder()
                        .setKeyStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/aisecconnector1-keystore.p12").getPath()))
                        .setTrustStorePath(Paths.get(DapsDriverTest.class.getClassLoader().
                                getResource("ssl/client-truststore_new.p12").getPath()))
                        .setKeyStorePassword("password".toCharArray())
                        .setTrustStorePassword("password".toCharArray())
                        .setKeyAlias("1")
                        .setKeyPassword("password".toCharArray())
                        .setDapsUrl("https://daps.aisec.fraunhofer.de")
                        .setSecurityRequirements(requirements)
                        .build();

        DapsDriver dapsDriver = new DefaultDapsDriver(config);
        String token = new String(dapsDriver.getToken());
        System.out.println(token);

        long ret;
        if (0 > (ret = dapsDriver.verifyToken(token.getBytes(), null))) {
            System.out.println("failed");
        } else {
            System.out.println("success: " + ret);
        }
    }
}
