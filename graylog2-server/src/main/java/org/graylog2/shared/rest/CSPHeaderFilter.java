package org.graylog2.shared.rest;

import org.graylog2.configuration.HttpConfiguration;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;

public class CSPHeaderFilter implements ContainerResponseFilter {

    private final HttpConfiguration httpConfiguration;

    @Inject
    public CSPHeaderFilter(HttpConfiguration httpConfiguration) {
        this.httpConfiguration = httpConfiguration;
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        responseContext.getHeaders().add(
                "Content-Security-Policy",
                "default-src 'self' ; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; img-src 'self' data:");
    }
}
