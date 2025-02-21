package org.graylog2.security.oidc;

public class OidcUtils {

    public static final String extractUsernameIfURN(final String urn) {
            if(!urn.contains(":")) {
                return urn;
            }
            String[] splits = urn.split(":");
            return splits[splits.length-1];
    }


    private OidcUtils() {}
}
