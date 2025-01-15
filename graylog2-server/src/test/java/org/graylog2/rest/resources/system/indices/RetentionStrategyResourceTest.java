package org.graylog2.rest.resources.system.indices;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.graylog2.audit.AuditEventSender;
import org.graylog2.contentpacks.jersey.ModelIdParamConverter;
import org.graylog2.indexer.indices.Indices;
import org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.indexer.retention.RetentionStrategy;
import org.graylog2.plugin.system.NodeId;
import org.graylog2.rest.models.system.indices.RetentionStrategyDescription;
import org.graylog2.shared.system.activities.ActivityWriter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import javax.inject.Provider;
import java.util.HashMap;
import java.util.Map;

public class RetentionStrategyResourceTest {



    private RetentionStrategyResource retentionStrategyResource;

    private Map<String, Provider<RetentionStrategy>> providers = new HashMap<>();

    private ObjectMapper objectMapper;

    @Mock
    ClusterConfigService clusterConfigService;
    @Mock
    Indices indices;
    @Mock
    ActivityWriter activityWriter;
    @Mock
    NodeId nodeId;
    @Mock
    AuditEventSender auditEventSender;

    @Before
    public void setup() {
        Map<String, Provider<RetentionStrategy>> providers = new HashMap<>();
        objectMapper = new ObjectMapper();
        clusterConfigService = Mockito.mock(ClusterConfigService.class);
        indices = Mockito.mock(Indices.class);
        activityWriter = Mockito.mock(ActivityWriter.class);
        nodeId = Mockito.mock(NodeId.class);
        auditEventSender = Mockito.mock(AuditEventSender.class);

        Provider<RetentionStrategy> deleteProvider = () -> new DeletionRetentionStrategy(indices, activityWriter, nodeId, auditEventSender);

        providers.put("delete", deleteProvider);

        retentionStrategyResource = new RetentionStrategyResource(providers, objectMapper, clusterConfigService);
    }


    @Test
    public void testGetDeletionRetentionStrategies() {
        RetentionStrategyDescription description = retentionStrategyResource.configSchema("delete");

        Assert.assertNotNull(description);
        Assert.assertTrue(description.jsonSchema().isObjectSchema());
    }


}
