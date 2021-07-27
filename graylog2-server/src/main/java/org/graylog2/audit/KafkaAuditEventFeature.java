package org.graylog2.audit;

import org.graylog2.audit.jersey.AuditEvent;

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.lang.reflect.Method;

public class KafkaAuditEventFeature implements DynamicFeature {

    public KafkaAuditEventFeature() {
    }


    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        Method resourceMethod = resourceInfo.getResourceMethod();
        if (resourceMethod != null && resourceMethod.isAnnotationPresent(AuditEvent.class)) {
            context.register(KafkaAuditEventFilter.class);
        }
    }

}
