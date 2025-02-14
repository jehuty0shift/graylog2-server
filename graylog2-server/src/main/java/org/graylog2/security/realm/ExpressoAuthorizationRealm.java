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
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.graylog2.security.CaffeineShiroCacheManager;
import org.graylog2.security.ExpressoPermissionResolver;
import org.graylog2.shared.security.SessionAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

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

        SessionIdHolder holder = principalCollection.oneByType(SessionIdHolder.class);
        if (holder == null) {
            log.trace("Holder is null, returning for principals {}", principalCollection.asList());
            return null;
        }

        if (log.isDebugEnabled()) {
            log.debug("Using Expresso Realm for session {}", holder.getSessionId());
        }


        Session session = SecurityUtils.getSubject().getSession();
        if (log.isTraceEnabled()) {
            log.trace("sessionId of subject {}", session.getId());
            log.trace("session Attributes {}", session.getAttributeKeys());
        }

        final String oidcProvider = (String) session.getAttribute(SessionAttributes.SESSION_OIDC_PROVIDER);

        if (oidcProvider == null || "ldp".equals(oidcProvider) || !holder.getSessionId().equals(session.getId())) {
            log.debug("Not a Session created through SessionAttribute Provider. Holder: {}, session {}", holder.getSessionId(), session.getId());
            return null;
        }

        final SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        log.debug("retrieving tokens with token from access Provider {}", oidcProvider);
        Boolean isExternal = (Boolean) session.getAttribute(SessionAttributes.SESSION_IS_EXTERNAL_USER);
        if (isExternal == null || !isExternal) {
            log.debug("session doesn't have any Expresso expected attributes");
            return null;
        }

        String accessToken = (String) session.getAttribute(SessionAttributes.OIDC_ACCESS_TOKEN);


        Set<Permission> permissions = expressoPermissionResolver.resolvePermissionsForPrincipal(accessToken);
        log.debug("retrieved {} permissions from expresso", permissions.size());
        info.setObjectPermissions(permissions);


        return info;
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
            Collection<Permission> perms = getPermissions(info);
            if (perms != null && !perms.isEmpty()) {
                if (perms.size() > 1000) {
                    return perms.stream().parallel().anyMatch(p -> p.implies(permission));
                } else {
                    for (Permission perm : perms) {
                        if (perm.implies(permission)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        return null;
    }
}
