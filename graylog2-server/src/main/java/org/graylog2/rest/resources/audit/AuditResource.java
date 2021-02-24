package org.graylog2.rest.resources.audit;


import com.codahale.metrics.annotation.Timed;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.graylog2.audit.KafkaAuditEventReader;
import org.graylog2.audit.KafkaAuditMessage;
import org.graylog2.rest.models.audit.response.AuditResponse;
import org.graylog2.rest.models.audit.response.AuditResponses;
import org.graylog2.shared.rest.resources.RestResource;
import org.graylog2.shared.security.RestPermissions;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@RequiresAuthentication
@Path("/audit")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Api(value = "audit", description = "System Audit")
public class AuditResource extends RestResource {

    private static final Logger log = LoggerFactory.getLogger(AuditResource.class);

    private final KafkaAuditEventReader kafkaAuditEventReader;

    @Inject
    public AuditResource(KafkaAuditEventReader kafkaAuditEventReader) {
        this.kafkaAuditEventReader = kafkaAuditEventReader;
    }

    @GET
    @Timed
    @Path("/messages")
    @RequiresPermissions(RestPermissions.STREAMS_CREATE)
    @ApiOperation(value = "return the last audit messages")
    public AuditResponses getMessages(@ApiParam(name = "size") @QueryParam("size") @DefaultValue("20") int size,
                                      @ApiParam(name = "from") @QueryParam("from") @DefaultValue("0") int from
                                      ) {
        log.info("user {} asked for {}  audit messages since {}",getCurrentUser(), size,from);
        Instant dateFrom = Instant.ofEpochMilli(from*1000L);

        List<KafkaAuditMessage> auditMessageList = kafkaAuditEventReader.pollLastAuditMessages(size,dateFrom);

        log.debug("retrieved {} messages",auditMessageList.size());

        return AuditResponses.create(auditMessageList.stream().map(AuditResource::kafkaAuditToAuditResp).collect(Collectors.toList()));
    }




    private static AuditResponse kafkaAuditToAuditResp(final KafkaAuditMessage kAuditMessage) {

        return AuditResponse.create(kAuditMessage.getStatus().name(),
                new DateTime(kAuditMessage.getTimestamp().toEpochMilli(), DateTimeZone.UTC),
                kAuditMessage.getClientId(),
                kAuditMessage.getShortMessage(),
                kAuditMessage.getNamespace(),
                kAuditMessage.getNodeName(),
                kAuditMessage.getObject(),
                kAuditMessage.getActor(),
                kAuditMessage.getAction(),
                kAuditMessage.getContext());
    }

}
