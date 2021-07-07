/**
 * This file is part of Graylog.
 * <p>
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * <p>
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog2.security.realm;

import com.google.common.collect.ImmutableMap;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.AllPermission;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.graylog2.audit.AuditActor;
import org.graylog2.audit.AuditEventSender;
import org.graylog2.audit.AuditEventType;
import org.graylog2.audit.AuditEventTypes;
import org.graylog2.users.UserImpl;
import org.graylog2.utilities.IpSubnet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.Set;

public class RootAccountRealm extends SimpleAccountRealm {
    private static final Logger LOG = LoggerFactory.getLogger(RootAccountRealm.class);
    public static final String NAME = "root-user";

    private final Set<IpSubnet> rootLoginAllowedIps;
    private final AuditEventSender auditEventSender;
    private final String rootUsername;

    @Inject
    RootAccountRealm(@Named("root_username") String rootUsername,
                     @Named("root_password_sha2") String rootPasswordSha2,
                     @Named("root_login_allowed_ips") Set<IpSubnet> rootLoginAllowedIps,
                     AuditEventSender auditEventSender) {
        this.rootLoginAllowedIps = rootLoginAllowedIps;
        this.auditEventSender = auditEventSender;
        this.rootUsername = rootUsername;

        setCachingEnabled(false);
        setCredentialsMatcher(new HashedCredentialsMatcher("SHA-256"));
        setName("root-account-realm");

        addRootAccount(rootUsername, rootPasswordSha2);
    }

    private void addRootAccount(String username, String password) {
        LOG.debug("Adding root account named {}, having all permissions", username);
        add(new SimpleAccount(
                username,
                password,
                getName(),
                CollectionUtils.asSet("root"),
                CollectionUtils.<Permission>asSet(new AllPermission())
        ));
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

            final AuthenticationInfo authenticationInfo = super.doGetAuthenticationInfo(token);
            final UsernamePasswordToken uPToken = (UsernamePasswordToken) token;
            final Map<String, Object> details = ImmutableMap.of(
                    "remote_address", uPToken.getHost());

            if (rootUsername.equals(uPToken.getUsername()) && !rootLoginAllowedIps.isEmpty() && !inTrustedSubnets(rootLoginAllowedIps, uPToken.getHost())) {
                auditEventSender.failure(AuditActor.user(rootUsername), "Attempt to login as root user from an untrusted IP, denying");
                LOG.warn("Attempt to login as root user from an untrusted IP: {}, denying", uPToken.getHost(), details);
                return null;
            }

            // After successful authentication and valid network, exchange the principals to unique admin userId
            if (authenticationInfo instanceof SimpleAccount) {
                SimpleAccount account = (SimpleAccount) authenticationInfo;
                account.setPrincipals(new SimplePrincipalCollection(UserImpl.LocalAdminUser.LOCAL_ADMIN_ID, NAME));
                auditEventSender.success(AuditActor.user(rootUsername), AuditEventTypes.AUTHENTICATION_CHECK, details);
                return account;
            }

            LOG.warn("no root account found !");
            auditEventSender.failure(AuditActor.user(rootUsername), AuditEventTypes.AUTHENTICATION_CHECK, details);
            return null;
    }

    private boolean inTrustedSubnets(Set<IpSubnet> trustedSubnet, String remoteAddr) {
        return trustedSubnet.stream().anyMatch(ipSubnet -> ipSubnetContains(ipSubnet, remoteAddr));
    }

    private boolean ipSubnetContains(IpSubnet ipSubnet, String ipAddr) {
        try {
            return ipSubnet.contains(ipAddr);
        } catch (UnknownHostException ignored) {
            LOG.debug("Looking up remote address <{}> failed.", ipAddr);
            return false;
        }
    }
}
