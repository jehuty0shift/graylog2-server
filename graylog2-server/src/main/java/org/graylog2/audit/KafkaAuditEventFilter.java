package org.graylog2.audit;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http.server.Response;
import org.glassfish.jersey.server.ExtendedUriInfo;
import org.graylog2.audit.jersey.AuditEvent;
import org.graylog2.plugin.database.users.User;
import org.graylog2.rest.RestTools;
import org.graylog2.shared.users.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.container.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class KafkaAuditEventFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private final KafkaAuditEventSender auditSender;
    private final ResourceInfo resourceInfo;
    private final ExtendedUriInfo extendedUriInfo;
    private final Response response;
    private final ObjectMapper objMapper;
    private final UserService userService;
    private JsonNode requestObj;


    private static final Logger LOG = LoggerFactory.getLogger(KafkaAuditEventFilter.class);

    @Inject
    public KafkaAuditEventFilter(KafkaAuditEventSender auditSender, @Context ExtendedUriInfo extendedUriInfo, @Context ResourceInfo resourceInfo, @Context Response response, UserService userService) {
        this.auditSender = auditSender;
        this.extendedUriInfo = extendedUriInfo;
        this.resourceInfo = resourceInfo;
        this.response = response;
        this.userService = userService;
        this.objMapper = new ObjectMapper();
    }


    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {

        requestObj = objMapper.createObjectNode();
        if (resourceInfo.getResourceMethod() != null
                && resourceInfo.getResourceMethod().isAnnotationPresent(AuditEvent.class)
                && resourceInfo.getResourceMethod().getAnnotation(AuditEvent.class).captureRequestContext()
                && MediaType.APPLICATION_JSON_TYPE.equals(containerRequestContext.getMediaType())
                && containerRequestContext.hasEntity()) {
            //Assumes content is json.
            try {
                byte[] outputBuffer = ByteStreams.toByteArray(containerRequestContext.getEntityStream());
                ByteArrayInputStream bais = new ByteArrayInputStream(outputBuffer);
                containerRequestContext.setEntityStream(bais);
                requestObj = objMapper.reader().readTree(bais);
            } catch (IOException ex) {
                LOG.warn("couldn't serialize request content from {}:{}", containerRequestContext.getUriInfo().getAbsolutePath().toString(), containerRequestContext.getMethod());
            }
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        if (resourceInfo.getResourceMethod() != null && resourceInfo.getResourceMethod().isAnnotationPresent(AuditEvent.class)) {
            try {
                LOG.debug("auditing request {}", requestContext.getUriInfo().getAbsolutePath().toString());
                AuditEvent auditEvent = resourceInfo.getResourceMethod().getAnnotation(AuditEvent.class);
                AuditActor auditActor = (auditEvent.actor() != null && !auditEvent.actor().equals("")) ? AuditActor.user(auditEvent.actor()) : resolveActor(requestContext);

                String remoteAddress = extractRemoteFromHeader(response.getRequest());
                Map<String, Object> auditContext = new HashMap<>();
                auditContext.put("remote_address", remoteAddress);
                if (!extendedUriInfo.getPathParameters().isEmpty()) {
                    auditContext.put("path_params", extendedUriInfo.getPathParameters());
                }

                if (!extendedUriInfo.getQueryParameters().isEmpty()) {
                    auditContext.put("query_params", extendedUriInfo.getQueryParameters());
                }

                auditContext.put("base_uri", extendedUriInfo.getBaseUri());
                auditContext.put("uri_path", extendedUriInfo.getPath());

                if (auditEvent.captureRequestContext() && !requestObj.isEmpty()) {
                    auditContext.put("request_entity", requestObj);
                }

                if (responseContext.hasEntity() && auditEvent.captureResponseEntity() && responseContext.getMediaType().equals(MediaType.APPLICATION_JSON)) {
                    if (!responseContext.getEntityClass().equals(Void.class) && !responseContext.getEntityClass().equals(Void.TYPE)) {
                        try {
                            String responseEntity = objMapper.writer().writeValueAsString(responseContext.getEntity());
                            auditContext.put("response_entity", responseEntity);
                        } catch (IOException ex) {
                            LOG.warn("couldn't serialize response {}", responseContext.getEntity().toString());
                        }
                    }
                }

                switch (responseContext.getStatusInfo().getFamily()) {
                    case CLIENT_ERROR:
                    case SERVER_ERROR:
                        auditSender.failure(auditActor, AuditEventType.create(auditEvent.type()), auditContext);
                        break;
                    default:
                        auditSender.success(auditActor, AuditEventType.create(auditEvent.type()), auditContext);
                }
            } catch (Exception ex) {
                LOG.error("Couldn't Send audit log to Kafka of method: {} /path: {} due to {}",requestContext.getMethod(), requestContext.getUriInfo(), ex);
            }
        }

    }

    private AuditActor resolveActor(ContainerRequestContext requestContext) {

        String userId = RestTools.getUserIdFromRequest(requestContext);
        if (userId == null || userId.equals("")) {
            return AuditActor.user("UNKNOWN");
        }
        User user = userService.loadById(userId);
        if (user == null) {
            return AuditActor.user(userId);
        }
        return AuditActor.user(user.getName());
    }

    private String extractRemoteFromHeader(Request request) {
        String headerName = "X-Forwarded-For";
        return request.getHeader(headerName) != null ? request.getHeader(headerName) : request.getRemoteAddr();
    }


}
