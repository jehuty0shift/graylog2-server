package org.graylog.security.authservice;

import com.mongodb.DuplicateKeyException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.graylog.security.authservice.test.AuthServiceBackendTestResult;
import org.graylog2.audit.AuditActor;
import org.graylog2.audit.AuditDetailKey;
import org.graylog2.audit.AuditEventSender;
import org.graylog2.audit.AuditEventTypes;
import org.graylog2.security.oidc.OidcProviderHandler;
import org.graylog2.security.oidc.OidcUtils;
import org.graylog2.security.realm.HTTPHeaderJWTAuthenticatingRealm;
import org.graylog2.users.RoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class IdTokenJwtServiceAuthenticator implements AuthServiceBackend {

    public static final String TYPE_NAME = "id_token_jwt";
    public static final String BACKEND_ID = "000000000000000000000002";

    private static final Logger log = LoggerFactory.getLogger(IdTokenJwtServiceAuthenticator.class);
    private static final String PREFERRED_USERNAME_CLAIM = "preferred_username";

    private final AuditEventSender auditEventSender;
    private final RoleService roleService;
    private final OidcProviderHandler providerHandler;
    private static final String UNKNOWN_USER = "unknown";


    @Inject
    public IdTokenJwtServiceAuthenticator(final AuditEventSender auditEventSender, final RoleService roleService, final OidcProviderHandler providerHandler) {
        this.auditEventSender = auditEventSender;
        this.roleService = roleService;
        this.providerHandler = providerHandler;
    }

    @Override
    public Optional<UserDetails> authenticateAndProvision(AuthServiceCredentials authCredentials, ProvisionerService provisionerService) {

        if (authCredentials.password().value() == null || authCredentials.password().value().isEmpty()) {
            log.warn("auth Credentials are empty");
            return Optional.empty();
        }

        final String jwtToken = authCredentials.password().value();

        JWT jwt = null;
        try {

            log.debug("Parsing token {}", jwtToken);

            jwt = JWTParser.parse(jwtToken);

            // Will check signature, Issuer and timestamp.
            IDTokenClaimsSet userClaims = providerHandler.validateJWT(jwt).orElseThrow(() -> new ParseException("BadToken", 0));
            log.debug("Claims valid for subject {}", userClaims.getSubject());

            final String username = extractUsernameFromClaims(userClaims);

            // if no exception here, it means the user is valid, we can safely provide the user.
            Map<String, Object> details = Map.of(
                    "auth_realm", this.getClass().toString());
            if (authCredentials.mustAuditSuccess()) {
                auditEventSender.success(AuditActor.user(username), AuditEventTypes.AUTHENTICATION_CHECK, details);
            }

            UserDetails userDetails = provisionerService.provision(provisionerService.newDetails(this)
                    .authServiceId(backendId())
                    .authServiceType(backendType())
                    .base64AuthServiceUid(com.nimbusds.jose.util.Base64.encode(userClaims.getSubject().getValue()).toString())
                    .fullName(Optional.ofNullable(userClaims.getStringClaim("name")).orElse(username))
                    .username(username)
                    .defaultRoles(Set.of(roleService.getReaderRoleObjectId()))
                    .email(Optional.ofNullable(userClaims.getStringClaim("email")).orElse(username + "@observability.ovhcloud.com"))
                    .accountIsEnabled(true)
                    .build());

            return Optional.of(userDetails);

        } catch (ParseException ex) {
            Map<String, Object> details = Map.of(AuditDetailKey.AUTH_REALM, HTTPHeaderJWTAuthenticatingRealm.class.toString(), AuditDetailKey.REASON, "incorrect token");
            auditEventSender.failure(AuditActor.user(UNKNOWN_USER), AuditEventTypes.AUTHENTICATION_CHECK, details);
            log.error("token {} is incorrect", jwtToken);
            return Optional.empty();
        } catch (BadJOSEException ex) {
            Map<String, Object> details = Map.of(AuditDetailKey.AUTH_REALM, HTTPHeaderJWTAuthenticatingRealm.class.toString(), AuditDetailKey.REASON, "invalid claims");
            final String username = extractUserFromJwt(jwt);
            auditEventSender.failure(AuditActor.user(username), AuditEventTypes.AUTHENTICATION_CHECK, details);
            log.error("JWT Claim of {} is incorrect", username);
            return Optional.empty();
        } catch (JOSEException ex) {
            Map<String, Object> details = Map.of(AuditDetailKey.AUTH_REALM, HTTPHeaderJWTAuthenticatingRealm.class.toString(), AuditDetailKey.REASON, "processing error");
            final String username = extractUserFromJwt(jwt);
            auditEventSender.failure(AuditActor.user(username), AuditEventTypes.AUTHENTICATION_CHECK, details);
            log.error("processing error", ex);
            return Optional.empty();
        } catch (DuplicateKeyException ex) {
            final String username = extractUserFromJwt(jwt);
            log.error("This user has been added multiple time {}", username, ex);
            return Optional.empty();
        }
    }

    private String extractUsernameFromClaims(IDTokenClaimsSet userClaims) {
        if (userClaims.getStringClaim(PREFERRED_USERNAME_CLAIM) != null) {
            return OidcUtils.extractUsernameIfURN(userClaims.getStringClaim(PREFERRED_USERNAME_CLAIM));
        } else {
            return OidcUtils.extractUsernameIfURN(userClaims.getSubject().getValue());
        }
    }

    private String extractUserFromJwt(final JWT jwt) {
        if (jwt == null) {
            return UNKNOWN_USER;
        }
        try {
            final String username = jwt.getJWTClaimsSet() == null ? null : jwt.getJWTClaimsSet().getStringClaim(PREFERRED_USERNAME_CLAIM);
            if (username == null) {
                return OidcUtils.extractUsernameIfURN(jwt.getJWTClaimsSet().getSubject());
            } else {
                return OidcUtils.extractUsernameIfURN(username);
            }
        } catch (ParseException ex) {
            return UNKNOWN_USER;
        }
    }

    @Override
    public String backendType() {
        return TYPE_NAME;
    }

    @Override
    public String backendId() {
        return BACKEND_ID;
    }

    @Override
    public String backendTitle() {
        return "JWT Provisioner";
    }

    @Override
    public AuthServiceBackendDTO prepareConfigUpdate(AuthServiceBackendDTO existingBackend, AuthServiceBackendDTO newBackend) {
        return null;
    }

    @Override
    public AuthServiceBackendTestResult testConnection(@Nullable AuthServiceBackendDTO existingConfig) {
        return null;
    }

    @Override
    public AuthServiceBackendTestResult testLogin(AuthServiceCredentials credentials, @Nullable AuthServiceBackendDTO existingConfig) {
        return null;
    }
}
