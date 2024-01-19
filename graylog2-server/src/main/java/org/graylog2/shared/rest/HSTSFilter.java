package org.graylog2.shared.rest;

import org.graylog2.configuration.HttpConfiguration;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;

public class HSTSFilter implements ContainerResponseFilter {

    private final boolean isEnabled;
    private static final String HEADER_KEY = "strict-transport-security";
    private static final String HEADER_VALUE = "max-age=15768000";

    @Inject
    public HSTSFilter(HttpConfiguration httpConfiguration) {
        isEnabled = httpConfiguration.isHttpEnableTls();
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        if (isEnabled) {
            responseContext.getHeaders().add(HEADER_KEY, HEADER_VALUE);
        }
    }

}
