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
import java.util.*;

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

    private final Map<String, AuthApi> authApis;
    private final String ldpCluster;
    private final List<String> graylogIamActions;
    private final Timer expressoApiTimer;

    private final boolean enabled;


    @Inject
    public ExpressoPermissionResolver(@Named("oidc_providers") List<String> oidcProviders,
                                      @Named("expresso_urls") List<String> expressoUrls,
                                      @Named("expresso_root_path") String rootPath,
                                      @Named("expresso_auth_tokens") List<String> authTokens,
                                      @Named("expresso_ldp_cluster_tag") String ldpCluster,
                                      MetricRegistry metricRegistry) {


        log.info("Expresso URLs are: {}", expressoUrls);
        this.ldpCluster = ldpCluster;
        this.graylogIamActions = List.of(STREAM_READ_ACTIONS, DASHBOARD_READ_ACTIONS, DASHBOARD_UPDATE_ACTIONS);
        this.expressoApiTimer = metricRegistry.timer(MetricRegistry.name(ExpressoPermissionResolver.class, "get-permissions"));
        this.enabled = notEmptyList(oidcProviders) &&
                notEmptyList(expressoUrls) &&
                notEmptyList(authTokens) &&
                areSameSize(oidcProviders,"oidc_providers",expressoUrls,"expresso_urls") &&
                areSameSize(oidcProviders, "oidc_providers",authTokens, "expresso_auth_tokens") &&
                ldpCluster != null &&
                !ldpCluster.isBlank();
        log.info("Expresso Permission Resolver is: {}", enabled ? "enabled" : "disabled");

        if (!enabled) {
            authApis = Map.of();
            return;
        }

        authApis = new HashMap<>();

        for (int i = 0; i < oidcProviders.size(); i++) {
            final String oidcProvider = oidcProviders.get(i);
            ApiClient apiClient = getApiClient(expressoUrls.get(i), rootPath, authTokens.get(i));
            authApis.put(oidcProvider, new AuthApi(apiClient));
        }
    }

    private boolean notEmptyList(List<String> listToCheck) {
        return listToCheck != null && !listToCheck.isEmpty() && listToCheck.get(0) != null && !listToCheck.get(0).isBlank();
    }

    private boolean areSameSize(List<String> first, String firstName, List<String> second, String secondName) {
        if(first == null || second == null || first.size() != second.size()) {
            log.error("list {} and list {} are not the same size, {} vs {}",firstName,secondName,first,second);
            return false;
        }
        return true;

    }

    public boolean isEnabled() {
        return enabled;
    }

    public Set<Permission> resolvePermissionsForPrincipal(final String oidcProvider, String accessToken) {
        if (!enabled) {
            return Set.of();
        }
        AuthApi authApi = authApis.get(oidcProvider);
        if (authApi == null) {
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
