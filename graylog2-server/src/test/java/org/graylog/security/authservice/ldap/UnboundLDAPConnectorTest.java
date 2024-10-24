/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.security.authservice.ldap;

import com.google.common.collect.ImmutableSet;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.*;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.ApacheDSTestExtension;
import org.apache.directory.server.ldap.LdapServer;
import org.graylog.testing.ldap.LDAPTestUtils;
import org.graylog2.ApacheDirectoryTestServiceFactory;
import org.graylog2.security.encryption.EncryptedValue;
import org.graylog2.security.encryption.EncryptedValueService;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


@ExtendWith(ApacheDSTestExtension.class)
@CreateLdapServer(name ="UnboundLDAP", transports = {
        @CreateTransport(protocol = "LDAP")
})
@CreateDS(
        name = "LdapConnectorTest",
        factory = ApacheDirectoryTestServiceFactory.class, // Ensures a unique storage location
        partitions = {
                @CreatePartition(
                        name = "example.com",
                        suffix = "dc=example,dc=com",
                        contextEntry = @ContextEntry(
                                entryLdif = "dn: dc=example,dc=com\n" +
                                        "dc: example\n" +
                                        "objectClass: top\n" +
                                        "objectClass: domain\n\n"

                        ),
                        indexes = {
                                @CreateIndex(attribute = "objectClass"),
                                @CreateIndex(attribute = "dc"),
                                @CreateIndex(attribute = "ou")
                        }

                )
        },
        loadedSchemas = {
                @LoadSchema(name = "nis", enabled = true)
        }
)
@ApplyLdifFiles(LDAPTestUtils.BASE_LDIF)
public class UnboundLDAPConnectorTest extends AbstractLdapTestUnit {
    private static final Set<String> ENABLED_TLS_PROTOCOLS = ImmutableSet.of("TLSv1.2", "TLSv1.3");
    private static final String ADMIN_DN = "uid=admin,ou=system";
    private static final String ADMIN_PASSWORD = "secret";

    private UnboundLDAPConnector connector;
    private LDAPConnection connection;
    private final EncryptedValueService encryptedValueService = new EncryptedValueService("1234567890abcdef");

    @BeforeEach
    public void setUp() throws Exception {
        final LdapServer server = getLdapServer();
        final LDAPConnectorConfig.LDAPServer ldapServer = LDAPConnectorConfig.LDAPServer.create("localhost", server.getPort());
        final LDAPConnectorConfig connectorConfig = LDAPConnectorConfig.builder()
                .systemUsername(ADMIN_DN)
                .systemPassword(encryptedValueService.encrypt(ADMIN_PASSWORD))
                .transportSecurity(LDAPTransportSecurity.NONE)
                .verifyCertificates(false)
                .serverList(Collections.singletonList(ldapServer))
                .build();

        connector = new UnboundLDAPConnector(10000, ENABLED_TLS_PROTOCOLS, (host, validateHostname) -> null, encryptedValueService);
        connection = connector.connect(connectorConfig);
    }

    @AfterEach
    public void tearDown() throws Exception {
        connection.close();
    }

    @Test
    public void testUserLookup() throws Exception {
        final UnboundLDAPConfig searchConfig = UnboundLDAPConfig.builder()
                .userSearchBase("ou=users,dc=example,dc=com")
                .userSearchPattern("(&(objectClass=posixAccount)(uid={0}))")
                .userUniqueIdAttribute("entryUUID")
                .userNameAttribute("uid")
                .userFullNameAttribute("cn")
                .build();
        final LDAPUser entry = connector.searchUserByPrincipal(connection, searchConfig, "john").orElse(null);

        assertThat(entry).isNotNull();
        assertThat(entry.dn())
                .isNotNull()
                .isEqualTo("cn=John Doe,ou=users,dc=example,dc=com");
        assertThat(new String(Base64.getDecoder().decode(entry.base64UniqueId()), StandardCharsets.UTF_8))
                .isNotBlank()
                .matches("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}");
    }

    @Test
    public void testAuthenticateSuccess() throws LDAPException {
        final boolean authenticated = connector.authenticate(connection, "cn=John Doe,ou=users,dc=example,dc=com", encryptedValueService.encrypt("test"));
        assertThat(authenticated).isTrue();
    }

    @Test
    public void testAuthenticateFail() throws LDAPException {
        final boolean authenticated = connector.authenticate(connection, "cn=John Doe,ou=users,dc=example,dc=com", encryptedValueService.encrypt("wrongpass"));
        assertThat(authenticated).isFalse();
    }

    @Test
    public void authenticateThrowsIllegalArgumentExceptionIfPrincipalIsNull() {
        Assert.assertThrows("Binding with empty principal is forbidden.", IllegalArgumentException.class, () -> connector.authenticate(connection, null, encryptedValueService.encrypt("secret")));
    }

    @Test
    public void authenticateThrowsIllegalArgumentExceptionIfPrincipalIsEmpty() {
        Assert.assertThrows("Binding with empty principal is forbidden.", IllegalArgumentException.class, () -> connector.authenticate(connection, "", encryptedValueService.encrypt("secret")));
    }

    @Test
    public void authenticateThrowsIllegalArgumentExceptionIfCredentialsAreNull() {
        Assert.assertThrows("Binding with null credentials is forbidden.", IllegalArgumentException.class, () -> connector.authenticate(connection, "principal", null));
    }

    @Test
    public void authenticateThrowsIllegalArgumentExceptionIfCredentialsAreEmpty()  {
        Assert.assertThrows("Binding with empty credentials is forbidden.", IllegalArgumentException.class,() ->  connector.authenticate(connection, "principal", EncryptedValue.createUnset()));
    }
}
