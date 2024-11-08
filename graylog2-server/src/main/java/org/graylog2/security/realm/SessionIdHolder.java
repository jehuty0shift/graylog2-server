package org.graylog2.security.realm;

import java.io.Serializable;

public class SessionIdHolder implements Serializable {

    static final long serialVersionUID = 1L;

    public static final String SESSION_REALM_KEY = "session-id";

    public SessionIdHolder(final String sessionId) {
        this.sessionId = sessionId;
    }

    public String getSessionId() {
        return sessionId;
    }

    private String sessionId;



}
