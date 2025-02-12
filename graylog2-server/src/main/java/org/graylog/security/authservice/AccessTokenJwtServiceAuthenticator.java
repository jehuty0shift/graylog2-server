package org.graylog.security.authservice;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.graylog.security.authservice.test.AuthServiceBackendTestResult;
import org.graylog2.audit.AuditActor;
import org.graylog2.audit.AuditEventSender;
import org.graylog2.audit.AuditEventTypes;
import org.graylog2.security.oidc.OidcProviderHandler;
import org.graylog2.users.RoleService;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class AccessTokenJwtServiceAuthenticator implements AuthServiceBackend {
    public static final String TYPE_NAME = "access_token_jwt";
    public static final String BACKEND_ID = "000000000000000000000003";

    private static Logger log = LoggerFactory.getLogger(AccessTokenJwtServiceAuthenticator.class);

    private final AuditEventSender auditEventSender;
    private final RoleService roleService;
    private final OidcProviderHandler providerHandler;

    @Inject
    public AccessTokenJwtServiceAuthenticator(AuditEventSender auditEventSender, RoleService roleService, OidcProviderHandler providerHandler) {
        this.auditEventSender = auditEventSender;
        this.roleService = roleService;
        this.providerHandler = providerHandler;
    }

    @Override
    public Optional<UserDetails> authenticateAndProvision(AuthServiceCredentials authCredentials, ProvisionerService provisionerService) {

        if (authCredentials.username() == null || !authCredentials.username().startsWith(TYPE_NAME)) {
            return Optional.empty();
        }

        log.debug("Using AccessToken Authenticator");

        final String accessToken = authCredentials.password().value();
        final String idProvider = authCredentials.username().substring(TYPE_NAME.length() + 1);

        log.debug("idProvider is: {}",idProvider);

        final Optional<UserInfo> userInfoOpt = idProvider.isBlank() ? providerHandler.retrieveUserInfo(accessToken) : providerHandler.retrieveUserInfo(idProvider, accessToken);

        if (userInfoOpt.isEmpty()) {
            log.debug("couldn't retrieve any UserInfo");
            return Optional.empty();
        }

        UserInfo userInfo = userInfoOpt.get();
        final String username = extractUsernameFromUserInfo(userInfo);
        log.debug("retrieved username {} from provider {}", username, idProvider);
        // if no exception here, it means the user is valid, we can safely provide the user.
        Map<String, Object> details = Map.of(
                "auth_realm", this.getClass().toString());
        if (authCredentials.mustAuditSuccess()) {
            auditEventSender.success(AuditActor.user(username), AuditEventTypes.AUTHENTICATION_CHECK, details);
        }

        UserDetails userDetails = provisionerService.provision(provisionerService.newDetails(this)
                .authServiceId(backendId())
                .authServiceType(backendType())
                .base64AuthServiceUid(com.nimbusds.jose.util.Base64.encode(userInfo.getSubject().getValue()).toString())
                .fullName(Optional.ofNullable(userInfo.getName()).orElse(username))
                .username(username)
                .defaultRoles(Set.of(roleService.getReaderRoleObjectId()))
                .email(Optional.ofNullable(userInfo.getEmailAddress()).orElse(username + "@observability.ovhcloud.com"))
                .accountIsEnabled(true)
                .build());

        return Optional.of(userDetails);
    }

    private String extractUsernameFromUserInfo(final UserInfo userInfo) {
        if (userInfo.getPreferredUsername() != null) {
            return userInfo.getPreferredUsername();
        } else {
            return userInfo.getSubject().getValue();
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
        return "Access Token Provisioner";
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
