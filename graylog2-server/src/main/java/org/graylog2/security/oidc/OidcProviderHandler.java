package org.graylog2.security.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Singleton
public class OidcProviderHandler {

    private final Logger log = LoggerFactory.getLogger(OidcProviderHandler.class);

    private final Map<String, OidcProviderInfo> providersInfo;


    @Inject
    public OidcProviderHandler(@Named("oidc_providers") final List<String> oidcProviders,
                               @Named("oidc_client_ids") final List<String> clientIds,
                               @Named("oidc_client_secrets") final List<String> clientSecrets,
                               @Named("oidc_connect_urls") final List<String> oidcURLs) {
        this.providersInfo = new HashMap<>();
        if (oidcProviders == null || oidcProviders.isEmpty()) {
            return;
        }

        if (clientIds == null || oidcProviders.size() != clientIds.size()) {
            log.error("MISCONFIGURATION IN OIDC PROVIDERS:  SIZE OF OIDC providers and OIDC clientIds differ, {} vs {}", oidcProviders, clientIds);
            return;
        }

        if (clientSecrets == null || oidcProviders.size() != clientSecrets.size()) {
            log.error("MISCONFIGURATION IN OIDC PROVIDERS:  SIZE OF OIDC providers and OIDC clientSecrets differ, {} vs {}", oidcProviders, clientSecrets);
            return;
        }

        if (oidcURLs == null || oidcProviders.size() != oidcURLs.size()) {
            log.error("MISCONFIGURATION IN OIDC PROVIDERS:  SIZE OF OIDC providers and OIDC URLs differ, {} vs {}", oidcProviders, oidcURLs);
            return;
        }

        for (int i = 0; i < oidcProviders.size(); i++) {
            final String oidcProvider = oidcProviders.get(i);
            final String clientId = clientIds.get(i);
            final String oidcUrl = oidcURLs.get(i);
            try {
                ClientID cId = new ClientID(clientId);
                Issuer clientIssuer = new Issuer(oidcUrl);
                OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.resolve(clientIssuer);
                OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
                clientMetadata.setIDTokenJWSAlg(JWSAlgorithm.RS256); // should maybe be a configuration variable
                OIDCClientInformation clientInformation = new OIDCClientInformation(cId, clientMetadata);
                clientMetadata.setName(clientId);
                IDTokenValidator validator = IDTokenValidator.create(providerMetadata, clientInformation);
                OidcProviderInfo clientInfo = new OidcProviderInfo(oidcProvider, clientId, clientSecrets.get(i), oidcUrl, providerMetadata, validator);
                providersInfo.put(oidcUrl, clientInfo);
                log.info("Configured oidc {} with url {}", clientId, oidcUrl);
            } catch (IOException | GeneralException ex) {
                log.error("Couldn't add client {}", clientId, ex);
            }
        }

        log.info("Added oidc clients {}", providersInfo.keySet());
    }


    public Optional<IDTokenClaimsSet> validateJWT(final JWT jwt) throws ParseException, BadJOSEException, JOSEException {
        if (jwt.getJWTClaimsSet().getIssuer() == null) {
            log.error("No issuer, will not attempt to validate the token {}", jwt.getParsedString());
            return Optional.empty();
        }

        IDTokenValidator validator = providersInfo.get(jwt.getJWTClaimsSet().getIssuer()).getTokenValidator();
        if (validator == null) {
            log.error("Bearer token could not be validated for this issuer {}, the validator doesn't exist", jwt.getJWTClaimsSet().getIssuer());
            return Optional.empty();
        }

        return Optional.ofNullable(validator.validate(jwt, null));
    }

    public Optional<OidcProviderInfo> retrieveProviderInfoByClientId(final String clientId) {
        return providersInfo.values().stream().filter(pI -> pI.getClientId().equals(clientId)).findFirst();
    }


    public Optional<OidcProviderInfo> retrieveProviderInfoByProviderName(final String providerName) {
        return providersInfo.values().stream().filter(pI -> pI.getOidcProvider().equals(providerName)).findFirst();
    }

    public Optional<UserInfo> retrieveUserInfo(final String accessTokenString) {

        return providersInfo.keySet().stream().map(k ->
                        retrieveUserInfo(k, accessTokenString)
                ).filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst();
    }


    public Optional<UserInfo> retrieveUserInfo(final String idProvider, final String accessTokenString) {
        Optional<OidcProviderInfo> providerInfoOpt = retrieveProviderInfoByProviderName(idProvider);
        if (providerInfoOpt.isEmpty()) {
            return Optional.empty();
        }

        try {
            URI userInfoUri = providerInfoOpt.get().getOidcProviderMetadata().getUserInfoEndpointURI();
            BearerAccessToken token = new BearerAccessToken(accessTokenString);

            HTTPResponse httpResponse = new UserInfoRequest(userInfoUri, token).toHTTPRequest().send();

            UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

            if (!userInfoResponse.indicatesSuccess()) {
                ErrorObject errorObject = userInfoResponse.toErrorResponse().getErrorObject();
                log.error("UserInfo retrieval failed {} {}", errorObject.getCode(), errorObject.getDescription());
                return Optional.empty();
            }

            return Optional.of(userInfoResponse.toSuccessResponse().getUserInfo());

        } catch (IOException ex) {
            log.error("Error during UserInfo http retrieval", ex);
            return Optional.empty();
        } catch (com.nimbusds.oauth2.sdk.ParseException ex) {
            log.error("UserInfo retrieval parsing exception", ex);
            return Optional.empty();
        }

    }

}
