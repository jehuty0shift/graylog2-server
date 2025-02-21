package org.graylog2.security.realm;

import com.nimbusds.jwt.JWT;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.graylog.security.authservice.*;
import org.graylog2.audit.AuditActor;
import org.graylog2.audit.AuditDetailKey;
import org.graylog2.audit.AuditEventSender;
import org.graylog2.audit.AuditEventTypes;
import org.graylog2.security.encryption.EncryptedValue;
import org.graylog2.security.oidc.OidcProviderHandler;
import org.graylog2.security.oidc.OidcUtils;
import org.graylog2.shared.security.ActorAwareJwtToken;
import org.graylog2.shared.security.ShiroSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

public class SessionJWTAuthenticatingRealm extends AuthenticatingRealm {

    public static final String NAME = "session-jws-authentication-realm";
    private static final String UNKNOWN_USER = "unknown";
    private static final Logger log = LoggerFactory.getLogger(SessionJWTAuthenticatingRealm.class);

    private final AuditEventSender auditEventSender;
    private final IdTokenJwtServiceAuthenticator idTokenJwtServiceAuthenticator;
    private final AccessTokenJwtServiceAuthenticator accessTokenJwtServiceAuthenticator;
    private final AuthServiceAuthenticator authServiceAuthenticator;

    @Inject
    public SessionJWTAuthenticatingRealm(final AuthServiceAuthenticator authServiceAuthenticator, final AuditEventSender auditEventSender, final IdTokenJwtServiceAuthenticator idTokenJwtServiceAuthenticator, final AccessTokenJwtServiceAuthenticator accessTokenJwtServiceAuthenticator, final OidcProviderHandler oidcProviderHandler) {
        this.auditEventSender = auditEventSender;
        this.authServiceAuthenticator = authServiceAuthenticator;
        this.idTokenJwtServiceAuthenticator = idTokenJwtServiceAuthenticator;
        this.accessTokenJwtServiceAuthenticator = accessTokenJwtServiceAuthenticator;

        setAuthenticationTokenClass(ActorAwareJwtToken.class);
        setCachingEnabled(false);
        // Credentials will be matched via the authentication service itself so we don't need Shiro to do it
        setCredentialsMatcher(new AllowAllCredentialsMatcher());

        log.info("SessionJwt authorizer is enabled");
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        final ActorAwareJwtToken jwtToken = (ActorAwareJwtToken) authenticationToken;

        try {
            log.debug("Authenticating with {}",SessionJWTAuthenticatingRealm.class.getCanonicalName());

            JWT idTokenJwt = jwtToken.getIdTokenJwt();
            AuthServiceResult result;
            //explicitly choose the backend associated with JWT

            if (idTokenJwt.getJWTClaimsSet().getExpirationTime() == null || idTokenJwt.getJWTClaimsSet().getExpirationTime().before(new Date())) {
                log.debug("idToken is expired: Expiration time is before now (exp: {})",idTokenJwt.getJWTClaimsSet().getExpirationTime());
                final String idProvider = jwtToken.getIdProvider();
                AuthServiceCredentials authServiceCredentials = AuthServiceCredentials.create(AccessTokenJwtServiceAuthenticator.TYPE_NAME + "_"+idProvider, EncryptedValue.createUnEncrypted(jwtToken.getAccessTokenJwt().serialize()));
                result = authServiceAuthenticator.authenticate(authServiceCredentials, accessTokenJwtServiceAuthenticator);
            } else {
                log.debug("idToken is not expired");
                //we re-serialize the deserialized token but in case of session creation this is acceptable.
                AuthServiceCredentials authServiceCredentials = AuthServiceCredentials.create(IdTokenJwtServiceAuthenticator.TYPE_NAME, EncryptedValue.createUnEncrypted(idTokenJwt.serialize()));
                result = authServiceAuthenticator.authenticate(authServiceCredentials, idTokenJwtServiceAuthenticator);
            }

            if (result == null || !result.isSuccess()) {
                log.debug("Authentication failed with token {}",jwtToken);
                Map<String, Object> details = Map.of(AuditDetailKey.AUTH_REALM, SessionJWTAuthenticatingRealm.class.toString(), AuditDetailKey.REASON, "authentication_failed");
                final String username = extractUserFromJwt(jwtToken.getIdTokenJwt());
                auditEventSender.failure(AuditActor.user(username), AuditEventTypes.AUTHENTICATION_CHECK, details);
                return null;
            }

            if (log.isDebugEnabled()) {
                log.debug("Successfully authenticated username <{}> for user profile <{}> with backend <{}/{}/{}>",
                        result.username(), result.userProfileId(), result.backendTitle(), result.backendType(), result.backendId());
            }
            Map<String, Object> details = Map.of(
                    "auth_realm", this.getClass().toString(),
                    "identity_provider", jwtToken.getIdProvider(),
                    "remote_address", jwtToken.getRemoteAddress());
            auditEventSender.success(AuditActor.user(result.username()), AuditEventTypes.AUTHENTICATION_CHECK, details);

            // Setting this, will let the SessionResource know, that when a non-existing session is validated, it
            // should in fact create a session.
            ShiroSecurityContext.requestSessionCreation(true);

            return toAuthenticationInfo(result);

        } catch (Exception ex) {
            log.error("Impossible to authenticate {}",authenticationToken,ex);
            Map<String, Object> details = Map.of(AuditDetailKey.AUTH_REALM, SessionJWTAuthenticatingRealm.class.toString(), AuditDetailKey.REASON, "processing error");
            final String username = extractUserFromJwt(jwtToken.getIdTokenJwt());
            auditEventSender.failure(AuditActor.user(username), AuditEventTypes.AUTHENTICATION_CHECK, details);
            return null;
        }
    }

    private String extractUserFromJwt(final JWT jwt) {
        if (jwt == null) {
            return UNKNOWN_USER;
        }
        try {
            final String username = jwt.getJWTClaimsSet() == null ? null : jwt.getJWTClaimsSet().getStringClaim("preferred_username");
            if (username == null) {
                return OidcUtils.extractUsernameIfURN(jwt.getJWTClaimsSet().getSubject());
            } else {
                return OidcUtils.extractUsernameIfURN(username);
            }
        } catch (ParseException ex) {
            return UNKNOWN_USER;
        }
    }


    private AuthenticationInfo toAuthenticationInfo(AuthServiceResult result) {
        return new SimpleAccount(result.userProfileId(), null, NAME + "/" + result.backendType());
    }
}
