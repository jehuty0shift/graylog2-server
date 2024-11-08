package org.graylog2.shared.security;

import com.nimbusds.jwt.JWT;
import org.apache.shiro.session.Session;
import org.graylog2.audit.AuditActor;

import java.text.ParseException;

public class ActorAwareJwtToken implements ActorAwareAuthenticationToken, Auditable, SessionAttributeProvider {


    private final JWT idTokenJwt;
    private final JWT accessTokenJwt;
    private final int credentials;
    private final String username;
    private final String remoteAddress;
    private final String idProvider;

    public ActorAwareJwtToken(final JWT idTokenJwt, final JWT accessTokenJwt, final String remoteAddress, final String idProvider) throws ParseException {
        this.idTokenJwt = idTokenJwt;
        this.accessTokenJwt = accessTokenJwt;
        this.credentials = idTokenJwt.getJWTClaimsSet().getSubject().hashCode();
        String tokenUsername = idTokenJwt.getJWTClaimsSet().getStringClaim("preferred_username") == null ? null : idTokenJwt.getJWTClaimsSet().getStringClaim("preferred_username");
        if (tokenUsername == null) {
            tokenUsername = idTokenJwt.getJWTClaimsSet().getSubject();
        }
        this.username = tokenUsername;
        this.remoteAddress = remoteAddress;
        this.idProvider = idProvider;
    }

    @Override
    public AuditActor getActor() {
        return AuditActor.user(getUsername());
    }

    @Override
    public Object getPrincipal() {
        return getIdTokenJwt();
    }

    public JWT getIdTokenJwt() {
        return idTokenJwt;
    }

    public JWT getAccessTokenJwt() {
        return accessTokenJwt;
    }

    public String getIdProvider() {
        return idProvider;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    public String getUsername() {
        return username;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }


    @Override
    public String toString() {
        return "ActorAwareJwtToken{" +
                "idTokenJwt=" + idTokenJwt.serialize() +
                ", accessTokenJwt=" + accessTokenJwt.serialize() +
                ", idProvider='" + idProvider + '\'' +
                '}';
    }


    @Override
    public void addSessionAttributes(Session session) {
        session.setAttribute(SessionAttributes.SESSION_OIDC_PROVIDER, idProvider);
        session.setAttribute(SessionAttributes.SESSION_IS_EXTERNAL_USER, true);
        session.setAttribute(SessionAttributes.OIDC_ACCESS_TOKEN,accessTokenJwt.serialize());
    }
}
