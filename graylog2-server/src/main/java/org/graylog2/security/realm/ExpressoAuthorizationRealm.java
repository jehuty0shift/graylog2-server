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
import java.util.Set;

public class ExpressoAuthorizationRealm extends AuthorizingRealm {


    private final ExpressoPermissionResolver expressoPermissionResolver;
    private final Timer resolvePermissionTimer;

    private static final Logger log = LoggerFactory.getLogger(ExpressoAuthorizationRealm.class);

    public static final String NAME = "expresso-authorization-realm";

    @Inject
    public ExpressoAuthorizationRealm(ExpressoPermissionResolver expressoPermissionResolver,
                                      CaffeineShiroCacheManager cacheManager,
                                      MetricRegistry metricRegistry) {
        this.expressoPermissionResolver = expressoPermissionResolver;
        this.resolvePermissionTimer = metricRegistry.timer(MetricRegistry.name(ExpressoPermissionResolver.class, "retrieve-permissions"));
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

        final SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        Session session = SecurityUtils.getSubject().getSession();
        if (log.isTraceEnabled()) {
            log.trace("sessionId of subject {}", session.getId());
            log.trace("session Attributes {}",session.getAttributeKeys());
        }

        final String oidcProvider = (String)session.getAttribute(SessionAttributes.SESSION_OIDC_PROVIDER);
        if (holder.getSessionId().equals(session.getId()) && !"ldp".equals(oidcProvider)) {
            log.debug("retrieving tokens with token from access Provider {}", oidcProvider);
            Boolean isExternal = (Boolean) session.getAttribute(SessionAttributes.SESSION_IS_EXTERNAL_USER);
            if (isExternal == null || !isExternal) {
                log.warn("session doesn't have any Expresso expected attributes");
                return null;
            }

            String accessToken = (String) session.getAttribute(SessionAttributes.OIDC_ACCESS_TOKEN);

            try (Timer.Context ignored = resolvePermissionTimer.time()) {
                Set<Permission> permissions = expressoPermissionResolver.resolvePermissionsForPrincipal(accessToken);
                log.debug("retrieved {} permissions from expresso", permissions.size());
                info.setObjectPermissions(permissions);
            }
        } else {
            log.debug("there is no match (something strange happened). Holder: {}, session {}", holder.getSessionId(), session.getId());
            return null;
        }

        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        return null;
    }
}
