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
package org.graylog2.security.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.graylog2.shared.security.SessionIdToken;
import org.graylog2.shared.security.ShiroRequestHeadersBinder;
import org.graylog2.shared.users.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Optional;

public class SessionAuthenticator extends AuthenticatingRealm {
    private static final Logger LOG = LoggerFactory.getLogger(SessionAuthenticator.class);
    public static final String NAME = "mongodb-session";
    public static final String X_GRAYLOG_NO_SESSION_EXTENSION = "X-Graylog-No-Session-Extension";

    private final UserService userService;

    @Inject
    SessionAuthenticator(UserService userService) {
        this.userService = userService;
        // this realm either rejects a session, or allows the associated user implicitly
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
        setAuthenticationTokenClass(SessionIdToken.class);
        setCachingEnabled(false);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        SessionIdToken sessionIdToken = (SessionIdToken) token;
        SessionIdHolder holder = new SessionIdHolder(sessionIdToken.getSessionId());

        final Subject tempSubject = new Subject.Builder().sessionId(sessionIdToken.getSessionId()).buildSubject();
        final Session session = tempSubject.getSession(false);
        if (session == null) {
            LOG.debug("Invalid session. Either it has expired or did not exist.");
            return null;
        }

        final Object userId = tempSubject.getPrincipal();

        if (!userService.userExists(String.valueOf(userId))) {
            LOG.debug("No user with userId {} found for this session", userId);
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Found session for userId {}", userId);
        }

        final Optional<String> noSessionExtension = ShiroRequestHeadersBinder.getHeaderFromThreadContext(X_GRAYLOG_NO_SESSION_EXTENSION);
        if (noSessionExtension.isPresent() && "true".equalsIgnoreCase(noSessionExtension.get())) {
            LOG.debug("Not extending session because the request indicated not to.");
        } else {
            session.touch();
        }

        SimplePrincipalCollection principals = new SimplePrincipalCollection();
        principals.add(userId,NAME);
        principals.add(holder, SessionIdHolder.SESSION_REALM_KEY);

        final Subject boundSubject = new Subject.Builder().principals(new SimplePrincipalCollection(principals)).sessionId(sessionIdToken.getSessionId()).buildSubject();

        ThreadContext.bind(boundSubject);

        LOG.debug("all principals {}" ,principals);
        return new SimpleAccount(principals, null,NAME);
    }
}
