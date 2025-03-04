package org.graylog2.security.realm;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.graylog2.security.CaffeineShiroCacheManager;
import org.graylog2.security.ExpressoPermissionResolver;
import org.graylog2.security.oidc.OidcUtils;
import org.graylog2.shared.security.RestPermissions;
import org.graylog2.shared.security.SessionAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;

public class ExpressoAuthorizationRealm extends AuthorizingRealm {


    private final ExpressoPermissionResolver expressoPermissionResolver;
    private final Timer isPermittedTimer;


    private static final Logger log = LoggerFactory.getLogger(ExpressoAuthorizationRealm.class);

    public static final String NAME = "expresso-authorization-realm";

    @Inject
    public ExpressoAuthorizationRealm(ExpressoPermissionResolver expressoPermissionResolver,
                                      CaffeineShiroCacheManager cacheManager,
                                      MetricRegistry metricRegistry) {
        this.expressoPermissionResolver = expressoPermissionResolver;
        this.isPermittedTimer = metricRegistry.timer(MetricRegistry.name(ExpressoPermissionResolver.class, "isPermitted"));
        setCachingEnabled(true);
        setCacheManager(cacheManager);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        if (!expressoPermissionResolver.isEnabled()) {
            return null;
        }

        Optional<TokenWithProvider> accessToken = extractAccessTokenFromPrincipalCollection(principalCollection);
        if (accessToken.isEmpty()) {
            return null;
        }

        final SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        Set<Permission> permissions = expressoPermissionResolver.resolvePermissionsForPrincipal(accessToken.get().idProvider(), accessToken.get().token());
        log.debug("retrieved {} permissions from expresso", permissions.size());
        info.setObjectPermissions(permissions);


        return info;
    }

    private Optional<TokenWithProvider> extractAccessTokenFromPrincipalCollection(PrincipalCollection principalCollection) {
        Optional<String> sessionFromPrincipal = (Optional<String>) principalCollection.fromRealm(PrincipalRealmNames.SESSION_REALM_KEY).stream().findFirst();

        if (sessionFromPrincipal.isPresent()) {
            log.trace("Using Principal From Session for {}", sessionFromPrincipal.get());
            return extractAccessTokenWithProviderFromSessionId(sessionFromPrincipal.get());
        }

        Collection<Object> jwtPrincipalCollection = (Collection<Object>) principalCollection.fromRealm(PrincipalRealmNames.ACCESS_JWT_REALM_KEY);

        if (jwtPrincipalCollection != null && !jwtPrincipalCollection.isEmpty()) {
            return extractAccessTokenWithProviderFromAccessJwtRealm(principalCollection);
        }

        return Optional.empty();
    }

    private Optional<TokenWithProvider> extractAccessTokenWithProviderFromAccessJwtRealm(final PrincipalCollection principalCollection) {
        String accessToken = (String) principalCollection.fromRealm(PrincipalRealmNames.ACCESS_JWT_REALM_KEY).iterator().next();
        if (accessToken == null) {
            return Optional.empty();
        }

        Map<String, String> extraAttributes = (Map<String, String>) principalCollection.fromRealm(PrincipalRealmNames.EXTRA_ATTRIBUTES).iterator().next();
        if (extraAttributes == null || extraAttributes.containsKey(OidcUtils.OIDC_PROVIDER_ATTRIBUTE)) {
            return Optional.empty();
        }
        log.trace("Using Principal From Token for {} and extra attributes: {}", accessToken, extraAttributes);
        return Optional.of(new TokenWithProvider(extraAttributes.get(OidcUtils.OIDC_PROVIDER_ATTRIBUTE), accessToken));

    }


    private Optional<TokenWithProvider> extractAccessTokenWithProviderFromSessionId(String principalSessionId) {
        Session session = SecurityUtils.getSubject().getSession();
        if (log.isTraceEnabled()) {
            log.trace("sessionId of subject {}", session.getId());
            log.trace("session Attributes {}", session.getAttributeKeys());
        }

        final String oidcProvider = (String) session.getAttribute(SessionAttributes.SESSION_OIDC_PROVIDER);

        if (oidcProvider == null || "ldp".equals(oidcProvider) || !principalSessionId.equals(session.getId())) {
            log.debug("Not a Session created through SessionAttribute Provider. Holder: {}, session {}", principalSessionId, session.getId());
            return Optional.empty();
        }

        log.debug("retrieving tokens with token from access Provider {}", oidcProvider);
        Boolean isExternal = (Boolean) session.getAttribute(SessionAttributes.SESSION_IS_EXTERNAL_USER);
        if (isExternal == null || !isExternal) {
            log.debug("session doesn't have any Expresso expected attributes");
            return Optional.empty();
        }

        if (session.getAttribute(SessionAttributes.OIDC_ACCESS_TOKEN) == null) {
            return Optional.empty();
        }

        return Optional.of(new TokenWithProvider(oidcProvider, (String) session.getAttribute(SessionAttributes.OIDC_ACCESS_TOKEN)));
    }


    //visibility changed from private to protected per SHIRO-332
    @Override
    protected Collection<Permission> getPermissions(AuthorizationInfo info) {
        if (info != null && !info.getObjectPermissions().isEmpty()) {
            return Collections.unmodifiableCollection(info.getObjectPermissions());
        } else {
            return Collections.emptySet();
        }
    }


    //visibility changed from private to protected per SHIRO-332
    @Override
    protected boolean isPermitted(Permission permission, AuthorizationInfo info) {
        try (Timer.Context ignored = isPermittedTimer.time()) {
            if (permission instanceof WildcardPermission) {
                // Expresso checks only dashboard, decorators and streams
                WildcardPermission wildcardPerm = (WildcardPermission) permission;
                if (!mustHandlePermission(wildcardPerm)) {
                    return false;
                }

                Collection<Permission> perms = getPermissions(info);
                if (perms != null && !perms.isEmpty()) {
                    return perms.contains(wildcardPerm);
                }
            }
            return false;
        }
    }

    private boolean mustHandlePermission(WildcardPermission wildcardPerm) {
        final String permString = wildcardPerm.toString();
        return permString.startsWith(RestPermissions.STREAMS_READ) ||
                permString.startsWith(RestPermissions.DECORATORS_READ) ||
                permString.startsWith(RestPermissions.DASHBOARDS_READ);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        return null;
    }

    public static class TokenWithProvider {

        private String idProvider;
        private String token;

        public TokenWithProvider(String idProvider, String token) {
            this.idProvider = idProvider;
            this.token = token;
        }

        public String token() {
            return token;
        }

        public String idProvider() {
            return idProvider;
        }
    }
}
