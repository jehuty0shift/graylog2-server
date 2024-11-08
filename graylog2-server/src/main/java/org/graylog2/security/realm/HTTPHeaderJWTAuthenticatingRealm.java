package org.graylog2.security.realm;

import com.google.common.collect.ImmutableMap;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.graylog.security.authservice.AuthServiceAuthenticator;
import org.graylog.security.authservice.AuthServiceCredentials;
import org.graylog.security.authservice.AuthServiceResult;
import org.graylog.security.authservice.IdTokenJwtServiceAuthenticator;
import org.graylog2.audit.AuditActor;
import org.graylog2.audit.AuditDetailKey;
import org.graylog2.audit.AuditEventSender;
import org.graylog2.audit.AuditEventTypes;
import org.graylog2.security.encryption.EncryptedValue;
import org.graylog2.security.oidc.OidcProviderHandler;
import org.graylog2.shared.security.HttpHeadersToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
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
    private final IdTokenJwtServiceAuthenticator jwtServiceAuthBackend;


    @Inject
    public HTTPHeaderJWTAuthenticatingRealm(final AuthServiceAuthenticator authServiceAuthenticator, final OidcProviderHandler keyLocator, final AuditEventSender auditEventSender, final IdTokenJwtServiceAuthenticator jwtServiceAuthBackend) {
        this.auditEventSender = auditEventSender;
        this.authServiceAuthenticator = authServiceAuthenticator;
        this.jwtServiceAuthBackend = jwtServiceAuthBackend;

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

        Optional<String> bearerHeader = headerValue(headers, "Authorization");
        log.trace("Authorization header {}", bearerHeader);
        if (bearerHeader.isEmpty()) {
            return null;
        }
        final String jwtToken = bearerHeader.map(s -> s.substring(s.indexOf(BEARER))).orElseThrow();

        try {

            AuthServiceCredentials authServiceCredentials = AuthServiceCredentials.create("jwt", EncryptedValue.createUnEncrypted(jwtToken));

            //explicitly choose the backend associated with JWT
            AuthServiceResult result = authServiceAuthenticator.authenticate(authServiceCredentials, jwtServiceAuthBackend);
            if (!result.isSuccess()) {
                Map<String, Object> details = Map.of(AuditDetailKey.AUTH_REALM, SessionJWTAuthenticatingRealm.class.toString(), AuditDetailKey.REASON, "authentication_failed");
                final String username = result.username();
                auditEventSender.failure(AuditActor.user(username), AuditEventTypes.AUTHENTICATION_CHECK, details);
                return null;
            }

            if (log.isDebugEnabled()) {
                log.debug("Successfully authenticated username <{}> for user profile <{}> with backend <{}/{}/{}>",
                        result.username(), result.userProfileId(), result.backendTitle(), result.backendType(), result.backendId());
            }
            Map<String, Object> details = ImmutableMap.of(
                    "auth_realm", this.getClass().toString(),
                    "remote_address", headersToken.getRemoteAddr());
            auditEventSender.success(AuditActor.user(result.username()), AuditEventTypes.AUTHENTICATION_CHECK, details);

            return toAuthenticationInfo(result);

        } catch (Exception ex) {
            log.error("Did not succeed to authenticate user");
            return null;
        }
    }

    private Optional<String> headerValue(MultivaluedMap<String, String> headers, @Nullable String headerName) {
        if (headerName == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(headers.getFirst(headerName.toLowerCase(Locale.US)));
    }


    private AuthenticationInfo toAuthenticationInfo(AuthServiceResult result) {
        return new SimpleAccount(result.userProfileId(), null, NAME + "/" + result.backendType());
    }

}
