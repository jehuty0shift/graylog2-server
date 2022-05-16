package org.graylog2.shared.rest;

import org.graylog2.configuration.HttpConfiguration;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

public class CSPHeaderFilter implements ContainerRequestFilter, ContainerResponseFilter {

    public static final String CSP_NONCE = "cspNonce";
    private boolean isCSPEnabled;
    private SecureRandom secureRandom;

    @Inject
    public CSPHeaderFilter(HttpConfiguration httpConfiguration) {

        this.isCSPEnabled = httpConfiguration.isHttpEnableCSP();
        secureRandom = new SecureRandom();
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!isCSPEnabled) {
            return;
        }
        byte[] nonceArray = new byte[32];

        secureRandom.nextBytes(nonceArray);
        String nonce = Base64.getEncoder().encodeToString(nonceArray);
        requestContext.getHeaders().putSingle(CSP_NONCE, nonce);
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        if (!isCSPEnabled) {
            return;
        }
        
        String nonce = requestContext.getHeaders().getFirst(CSP_NONCE);

        responseContext.getHeaders().add(
                "Content-Security-Policy",
                "default-src 'self' ; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval' 'nonce-" + nonce + "'; img-src https://*.openstreetmap.org/ https://*.tile.openstreetmap.org/ 'self' data:");
    }
}
