package org.graylog2.rest.resources.system;

import com.codahale.metrics.annotation.Timed;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.graylog2.rest.models.system.ux.responses.UxStatusResponse;
import org.graylog2.shared.initializers.JerseyService;
import org.graylog2.shared.rest.resources.RestResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.ServiceUnavailableException;
import javax.ws.rs.core.MediaType;

@Api(value = "System/UX")
@Path("/system/ux")
@Produces(MediaType.APPLICATION_JSON)
@RequiresAuthentication
public class UxResource extends RestResource {

    private static final Logger LOG = LoggerFactory.getLogger(UxResource.class);
    private JerseyService jerseyService;

    @Inject
    public UxResource(JerseyService service) {
        this.jerseyService = service;
    }

    @GET
    @ApiOperation(value = "Retrieve the status of the UX.",
            notes = "Retrieve the status of the Web Interface (ie. the interface is up and running on localhost)")
    @Path("/status")
    public UxStatusResponse get() {
        final boolean active = jerseyService.isRunning();
        LOG.debug("get UX status : {}");
        if (active) {
            return UxStatusResponse.create(active);
        } else {
            throw new ServiceUnavailableException("Rest API and UX not available yet");
        }

    }

}
