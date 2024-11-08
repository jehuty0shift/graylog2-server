package org.graylog2.security;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.graylog2.security.expresso.client.ApiClient;
import org.graylog2.security.expresso.client.ApiException;
import org.graylog2.security.expresso.client.api.AuthApi;
import org.graylog2.security.expresso.client.auth.HttpBearerAuth;
import org.graylog2.security.expresso.client.model.ResourceListRequest;
import org.graylog2.security.expresso.client.model.ResourceListResult;
import org.graylog2.security.expresso.client.model.State;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Singleton
public class ExpressoPermissionResolver {

    private static final Logger log = LoggerFactory.getLogger(ExpressoPermissionResolver.class);

    private static final String STREAM_READ_ACTIONS = "ldp:graylog:stream/read";
    private static final String DASHBOARD_READ_ACTIONS = "ldp:graylog:dashboard/read";
    private static final String DASHBOARD_UPDATE_ACTIONS = "ldp:graylog:dashboard/update";

    private static final String STREAM_TYPE = "ldp/stream";
    private static final String DASHBOARD_TYPE = "ldp/dashboard";

    private static final String TAG_PREFIX = "ovh:ldp:";
    private static final String TAG_SUFFIX = ":graylogId";

    private static final String LDP_CLUSTER_TAG_KEY = "ovh:ldp:cluster:name";

    private final AuthApi authApi;
    private final String ldpCluster;
    private final List<String> graylogIamActions;
    private final Timer expressoApiTimer;

    private final boolean enabled;


    @Inject
    public ExpressoPermissionResolver(@Named("expresso_url") String expressoUrl,
                                      @Named("expresso_root_path") String rootPath,
                                      @Named("expresso_auth_token") String authToken,
                                      @Named("expresso_ldp_cluster_tag") String ldpCluster,
                                      MetricRegistry metricRegistry) {


        log.info("Expresso URL is: {}", expressoUrl);
        this.ldpCluster = ldpCluster;
        this.graylogIamActions = List.of(STREAM_READ_ACTIONS, DASHBOARD_READ_ACTIONS, DASHBOARD_UPDATE_ACTIONS);
        this.expressoApiTimer = metricRegistry.timer(MetricRegistry.name(ExpressoPermissionResolver.class,"get-permissions"));
        this.enabled = expressoUrl != null &&
                !expressoUrl.isBlank() &&
                authToken != null &&
                !authToken.isBlank() &&
                ldpCluster != null &&
                !ldpCluster.isBlank();
        log.info("Expresso Permission Resolver is: {}", enabled ? "enabled" : "disabled");

        if (!enabled) {
            authApi = null;
            return;
        }

        ApiClient apiClient = getApiClient(expressoUrl, rootPath, authToken);

        this.authApi = new AuthApi(apiClient);

    }


    public boolean isEnabled() {
        return enabled;
    }

    public Set<Permission> resolvePermissionsForPrincipal(String accessToken) {
        if (!enabled) {
            return Set.of();
        }
        ResourceListRequest resListRequest = new ResourceListRequest();
        resListRequest.actions(graylogIamActions);
        resListRequest.setToken(accessToken);
        resListRequest.setQueryContext(Map.of(LDP_CLUSTER_TAG_KEY, ldpCluster));

        log.trace("doing Expresso call with token {}", accessToken);

        try {
            List<ResourceListResult> results;
            try (Timer.Context ignored = expressoApiTimer.time()) {
                results = authApi.iamResourceListPost(resListRequest, null, 10000);
            }
            Set<Permission> permissions = new HashSet<>(results.size());

            for (ResourceListResult result : results) {
                log.trace("result: {}", result);
                if (STREAM_TYPE.equals(result.getResourceType())) {
                    permissions.addAll(permissionForStreamResource(result));
                } else if (DASHBOARD_TYPE.equals(result.getResourceType())) {
                    permissions.addAll(permissionForDashboardResource(result));
                }
            }

            return permissions;
        } catch (ApiException ex) {
            log.error("fatal error when trying to retrieve rights", ex);
        }

        return Set.of();
    }

    private static @NotNull ApiClient getApiClient(String expressoUrl, String rootPath, String authToken) {
        ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(expressoUrl + rootPath);
        if (!(apiClient.getAuthentication(HttpBearerAuth.NAME) instanceof HttpBearerAuth)) {
            throw new IllegalStateException("HttpAuthentication is not well configured");
        } else {
            HttpBearerAuth auth = (HttpBearerAuth) apiClient.getAuthentication(HttpBearerAuth.NAME);
            auth.setBearerToken(authToken == null ? "" : authToken);
        }
        return apiClient;
    }

    private Set<Permission> permissionForStreamResource(ResourceListResult result) {
        // decorators:read:streamId
        // decorators:edit:streamId
        // decorators:create:streamId
        // streams:read:streamId
        if (result.getResourceTags() == null) {
            //means there is no graylogId to build rights on
            return Set.of();
        }

        final String graylogId = result.getResourceTags().get(TAG_PREFIX + "stream" + TAG_SUFFIX);
        if (graylogId == null || graylogId.isBlank()) {
            return Set.of();
        }

        log.trace("graylog stream Id : {}", graylogId);
        if (State.OK.equals(result.getResourceState()) &&
                result.getAuthorizedActions() != null &&
                result.getAuthorizedActions().containsKey(STREAM_READ_ACTIONS) &&
                (result.getUnauthorizedActions() == null || !result.getUnauthorizedActions().contains(STREAM_READ_ACTIONS))) {
            return Set.of(
                    new WildcardPermission("decorators:read:" + graylogId),
                    new WildcardPermission("decorators:edit:" + graylogId),
                    new WildcardPermission("decorators:create:" + graylogId),
                    new WildcardPermission("streams:read:" + graylogId)
            );
        }

        return Set.of();
    }


    private Set<Permission> permissionForDashboardResource(ResourceListResult result) {
        // dashboard:read:dashID
        // dashboard:edit:dashID
        if (result.getResourceTags() == null) {
            // means there is no graylogId to build rights on
            return Set.of();
        }
        final String graylogId = result.getResourceTags().get(TAG_PREFIX + "dashboard" + TAG_SUFFIX);
        if (graylogId == null || graylogId.isBlank()) {
            return Set.of();
        }

        Set<Permission> permissions = new HashSet<>();
        log.debug("graylog dashboard Id : {}", graylogId);
        if (State.OK.equals(result.getResourceState()) && result.getAuthorizedActions() != null) {
            if (result.getAuthorizedActions().containsKey(DASHBOARD_READ_ACTIONS) &&
                    (result.getUnauthorizedActions() == null || !result.getUnauthorizedActions().contains(DASHBOARD_READ_ACTIONS))) {
                permissions.add(new WildcardPermission("dashboard:read:" + graylogId));
            }
            if (result.getAuthorizedActions().containsKey(DASHBOARD_UPDATE_ACTIONS) &&
                    (result.getUnauthorizedActions() == null || !result.getUnauthorizedActions().contains(DASHBOARD_UPDATE_ACTIONS))) {
                permissions.add(new WildcardPermission("dashboard:edit:" + graylogId));
            }

        }

        return permissions;
    }


}
