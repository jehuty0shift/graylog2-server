package org.graylog2.security.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.graylog.security.authservice.*;
import org.graylog.security.authservice.backend.AccessJwtAuthServiceBackend;
import org.graylog.security.authservice.backend.IdJwtAuthServiceBackend;
import org.graylog2.audit.AuditActor;
import org.graylog2.audit.AuditDetailKey;
import org.graylog2.audit.AuditEventSender;
import org.graylog2.audit.AuditEventTypes;
import org.graylog2.security.encryption.EncryptedValue;
import org.graylog2.shared.security.HttpHeadersToken;
import org.graylog2.shared.security.ShiroSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.MultivaluedMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public class HTTPHeaderJWTAuthenticatingRealm extends AuthenticatingRealm {

    public static final String NAME = "header-jws-authentication-realm";
    private static final Logger log = LoggerFactory.getLogger(HTTPHeaderJWTAuthenticatingRealm.class);
    private static final String BEARER = "Bearer ";
    private final AuditEventSender auditEventSender;
    private final AuthServiceAuthenticator authServiceAuthenticator;
    private final IdJwtAuthServiceBackend idJwtServiceAuthenticator;
    private final AccessJwtAuthServiceBackend accessJwtServiceAuthenticator;

    @Inject
    public HTTPHeaderJWTAuthenticatingRealm(final AuthServiceAuthenticator authServiceAuthenticator, final AuditEventSender auditEventSender, final IdJwtAuthServiceBackend idJwtServiceAuthenticator, final AccessJwtAuthServiceBackend accessJwtServiceAuthenticator) {
        this.auditEventSender = auditEventSender;
        this.authServiceAuthenticator = authServiceAuthenticator;
        this.idJwtServiceAuthenticator = idJwtServiceAuthenticator;
        this.accessJwtServiceAuthenticator = accessJwtServiceAuthenticator;

        setAuthenticationTokenClass(HttpHeadersToken.class);
        setCachingEnabled(false);
        // Credentials are matched via the authentication service itself so we don't need Shiro to do it, we just need to validate the creds
        setCredentialsMatcher(new AllowAllCredentialsMatcher());

        log.info("HeaderJWT authorizer is enabled");
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        final HttpHeadersToken headersToken = (HttpHeadersToken) authenticationToken;

        MultivaluedMap<String, String> headers = headersToken.getHeaders();

        Optional<String> bearerHeader = Optional.ofNullable(headers.getFirst("Authorization".toLowerCase(Locale.US)));
        log.trace("Authorization header {}", bearerHeader);
        if (bearerHeader.isEmpty()) {
            return null;
        }
        final String jwtToken = bearerHeader.filter(s -> s.startsWith(BEARER)).map(s -> s.substring(BEARER.length())).orElse(null);

        if (jwtToken == null) {
            return null;
        }

        try {

            //explicitly choose the backends associated with JWTs
            // AccessToken handling
            AuthServiceCredentials accessTokenCredentials = AuthServiceCredentials.create(AccessJwtAuthServiceBackend.TYPE_NAME + "_", EncryptedValue.createUnEncrypted(jwtToken));
            AuthServiceResult result = authServiceAuthenticator.authenticate(accessTokenCredentials, accessJwtServiceAuthenticator);
            if (result.isSuccess()) {
                return handleResultSuccess(result, headersToken, auditEventSender, jwtToken, result.extraAttributes());
            }

            log.debug("accessJWT failed {}", result);

            //Id Token handling
            AuthServiceCredentials idTokenCredentials = AuthServiceCredentials.create(IdJwtAuthServiceBackend.TYPE_NAME, EncryptedValue.createUnEncrypted(jwtToken));
            result = authServiceAuthenticator.authenticate(idTokenCredentials, idJwtServiceAuthenticator);

            if (result.isSuccess()) {
                return handleResultSuccess(result, headersToken, auditEventSender, jwtToken, result.extraAttributes());
            }

            log.debug("idJWT failed {}", result);

            Map<String, Object> details = Map.of(AuditDetailKey.AUTH_REALM, SessionJWTAuthenticatingRealm.class.toString(), AuditDetailKey.REASON, "authentication_failed");
            final String username = result.username();
            auditEventSender.failure(AuditActor.user(username), AuditEventTypes.AUTHENTICATION_CHECK, details);
            return null;

        } catch (Exception ex) {
            log.error("Did not succeed to authenticate user");
            return null;
        }
    }

    private AuthenticationInfo handleResultSuccess(AuthServiceResult result, HttpHeadersToken headersToken, AuditEventSender auditEventSender, final String jwtToken, final Map<String, String> extraAttributes) {
        Map<String, Object> details = Map.of(
                "auth_realm", this.getClass().toString(),
                "remote_address", headersToken.getRemoteAddr());
        auditEventSender.success(AuditActor.user(result.username()), AuditEventTypes.AUTHENTICATION_CHECK, details);
        SimplePrincipalCollection principals = new SimplePrincipalCollection();
        principals.add(result.userProfileId(),NAME);
        principals.add(jwtToken,PrincipalRealmNames.ACCESS_JWT_REALM_KEY);
        if (extraAttributes != null) {
            principals.add(Map.copyOf(extraAttributes),PrincipalRealmNames.EXTRA_ATTRIBUTES);
        }

        ShiroSecurityContext.requestSessionCreation(false);
        return new SimpleAccount(principals, null, NAME + "/" + result.backendType());
    }



}
