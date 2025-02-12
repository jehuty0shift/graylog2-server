package org.graylog2.security.oidc;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

public class OidcProviderInfo {

    private final String oidcProvider;
    private final String clientId;
    private final String clientSecret;
    private final String issuer;
    private final OIDCProviderMetadata oidcProviderMetadata;
    private final IDTokenValidator tokenValidator;

    public OidcProviderInfo(final String oidcProvider, String clientId, String clientSecret, String issuer, OIDCProviderMetadata oidcProviderMetadata, IDTokenValidator tokenValidator) {
        this.oidcProvider = oidcProvider;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.issuer = issuer;
        this.oidcProviderMetadata = oidcProviderMetadata;
        this.tokenValidator = tokenValidator;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public OIDCProviderMetadata getOidcProviderMetadata() {
        return oidcProviderMetadata;
    }

    public IDTokenValidator getTokenValidator() {
        return tokenValidator;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getOidcProvider() {
        return oidcProvider;
    }
}
