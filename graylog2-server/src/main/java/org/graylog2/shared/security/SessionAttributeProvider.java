package org.graylog2.shared.security;

import org.apache.shiro.session.Session;

public interface SessionAttributeProvider {
   void addSessionAttributes(final Session session);
}
