package org.graylog2.shared.security;

import org.apache.shiro.authc.UsernamePasswordToken;

public class AuditableUsernamePasswordToken extends UsernamePasswordToken implements Auditable {

    final boolean mustAudit;
    public AuditableUsernamePasswordToken(String username, String credential, String host, boolean mustAudit) {
        super(username,credential,host);
        this.mustAudit = mustAudit;
    }

    @Override
    public boolean mustAudit() {
        return this.mustAudit;
    }
}
