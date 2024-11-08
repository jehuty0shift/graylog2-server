package org.graylog2.rest.resources.system;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.shiro.session.Session;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.jersey.server.ContainerRequest;
import org.graylog2.audit.AuditEventTypes;
import org.graylog2.audit.jersey.AuditEvent;
import org.graylog2.audit.jersey.NoAuditEvent;
import org.graylog2.rest.RestTools;
import org.graylog2.rest.models.system.sessions.responses.SessionResponseFactory;
import org.graylog2.security.oidc.OidcProviderHandler;
import org.graylog2.security.oidc.OidcProviderInfo;
import org.graylog2.shared.rest.resources.RestResource;
import org.graylog2.shared.security.ActorAwareJwtToken;
import org.graylog2.shared.security.AuthenticationServiceUnavailableException;
import org.graylog2.shared.security.SessionCreator;
import org.graylog2.shared.security.ShiroSecurityContext;
import org.graylog2.utilities.IpSubnet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.validation.constraints.NotBlank;
import javax.ws.rs.*;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

@Path("/system/oidc")
@Api(value = "System/Oidc")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class OIDCResource extends RestResource {
    private static final Logger log = LoggerFactory.getLogger(OIDCResource.class);
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String AUTHORIZATION_CODE = "code";
    private static final String CODE_VERIFIER = "code_verifier";

    private final Request grizzlyRequest;
    private final SessionCreator sessionCreator;
    private final SessionResponseFactory sessionResponseFactory;
    private final Set<IpSubnet> trustedSubnets;
    private final OidcProviderHandler oidcProviderHandler;
    private final ObjectMapper objectMapper;

    public static final String CALLBACK_URL = "/callback";

    @Inject
    public OIDCResource(@Context Request grizzlyRequest, final SessionCreator sessionCreator, final OidcProviderHandler oidcProviderHandler, final SessionResponseFactory sessionResponseFactory, @Named("trusted_proxies") Set<IpSubnet> trustedSubnets, final ObjectMapper objectMapper) {
        this.grizzlyRequest = grizzlyRequest;
        this.sessionCreator = sessionCreator;
        this.sessionResponseFactory = sessionResponseFactory;
        this.trustedSubnets = trustedSubnets;
        this.oidcProviderHandler = oidcProviderHandler;
        this.objectMapper = objectMapper;
    }

    @POST
    @Path("/{idpProvider}/token")
    @ApiOperation(value = "Send code challenge to ")
    @AuditEvent(type = AuditEventTypes.OIDC_TOKEN_CREATE)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response forwardTokenCreation(@Context ContainerRequestContext requestContext, @ApiParam(name = "idpProvider") @PathParam("idpProvider") @NotBlank final String idpProvider) {

        if (requestContext instanceof ContainerRequest) {
            ContainerRequest request = (ContainerRequest) requestContext;
            log.debug("Media Type {}", request.getMediaType().getType());
            // Check if the request has an entity and is of type application/x-www-form-urlencoded
            if (request.hasEntity() && MediaType.APPLICATION_FORM_URLENCODED_TYPE.isCompatible(request.getMediaType())) {

                // Buffer the entity stream to allow multiple reads
                request.bufferEntity();
                Form form = request.readEntity(Form.class);
                validateForm(form);

                TokenRequest tokenRequest = buildTokenRequestFromForm(form, oidcProviderHandler);

                // Send the token request
                try {
                    HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
                    TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);


                    if (!tokenResponse.indicatesSuccess()) {
                        // Handle error response
                        TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                        log.error("Token request error: {}", errorResponse.getErrorObject());
                        throw new ForbiddenException("Token request error");
                    }

                    final String responseContent = httpResponse.getContent();
                    log.trace("Response from token creation {}", responseContent);

                    return Response.ok(responseContent, httpResponse.getEntityContentType().getType()).build();
                } catch (IOException ex) {
                    log.error("IO Exception during Token call", ex);
                    throw new ForbiddenException("Impossible to create the token");
                } catch (com.nimbusds.oauth2.sdk.ParseException ex) {
                    log.error("Parse Exception during token creation", ex);
                    throw new ForbiddenException("Problem during token creation");
                }
            }
        }
        log.error("Error with token Request {}", requestContext.getHeaders());
        return Response.status(Response.Status.FORBIDDEN).build();
    }

    @POST
    @Path("/login")
    @ApiOperation(value = "Initiate login session", notes = "This request initiate the login session with the token")
    @NoAuditEvent("dispatches audit events in the method body")
    public JsonNode initiateLogin(@Context ContainerRequestContext requestContext) {

        final SecurityContext securityContext = requestContext.getSecurityContext();
        if (!(securityContext instanceof ShiroSecurityContext)) {
            throw new InternalServerErrorException("Unsupported SecurityContext class, this is a bug!");
        }
        final ShiroSecurityContext shiroSecurityContext = (ShiroSecurityContext) securityContext;

        // we treat the BASIC auth username as the sessionid
        final String sessionId = shiroSecurityContext.getUsername();
        final String host = RestTools.getRemoteAddrFromRequest(grizzlyRequest, trustedSubnets);

        try {

            final String inputSTring = new String(grizzlyRequest.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            log.trace("Request content {}", inputSTring);

            JsonNode tokensNode = objectMapper.reader().readTree(inputSTring);

            if (tokensNode.isNull()) {
                throw new BadRequestException("Malformed token");
            }

            JsonNode accessTokenNode = tokensNode.get("access_token");
            JsonNode idTokenNode = tokensNode.get("id_token");
            JsonNode expiresAtNode = tokensNode.get("expires_at");
            JsonNode idProviderNode = tokensNode.get("idProvider");

            validateTokenNode(accessTokenNode, JsonNode::isTextual);
            validateTokenNode(idTokenNode, JsonNode::isTextual);
            validateTokenNode(idProviderNode, JsonNode::isTextual);
            validateTokenNode(expiresAtNode, JsonNode::isNumber);

            final String accessTokenString = accessTokenNode.asText();
            log.debug("received access_token {}", accessTokenString);

            final String idTokenString = idTokenNode.asText();
            log.debug("received id_token {}", idTokenString);

            final long expiresAt = expiresAtNode.asLong();
            log.debug("expires_at value {}", expiresAt);

            final String idProvider = idProviderNode.asText();

            ActorAwareJwtToken authToken = buildToken(idTokenString, accessTokenString, host, idProvider);
            log.debug("ActorAwareJwtToken properly built, will authenticate and create session");
            Optional<Session> session = sessionCreator.create(sessionId, host, authToken);
            if (session.isPresent()) {
                log.debug("session created");
                return sessionResponseFactory.forSession(session.get());
            } else {
                log.debug("session not created");
                throw new NotAuthorizedException("Invalid credentials.", "Basic realm=\"Graylog Server session\"");
            }
        } catch (AuthenticationServiceUnavailableException e) {
            throw new ServiceUnavailableException("Authentication service unavailable");
        } catch (ParseException ex) {
            log.error("cannot parse JWT token", ex);
            throw new BadRequestException("Malformed Bearer Token");
        } catch (IOException ex) {
            log.error("cannot parse Token body", ex);
            throw new WebApplicationException("Malformed Authentication");
        }
    }

    private void validateTokenNode(JsonNode tokenNode, Predicate<JsonNode> validator) {
        if (tokenNode.isMissingNode() || tokenNode.isNull() || !validator.test(tokenNode)) {
            throw new BadRequestException("Malformed token");
        }
    }


    private ActorAwareJwtToken buildToken(String idTokenString, String accessTokenString, String remoteAddress, String idProvider) throws ParseException {
        if (idTokenString.isEmpty()) {
            return null;
        }

        JWT idTokenJwt = JWTParser.parse(idTokenString);

        JWT accessTokenJwt = JWTParser.parse(accessTokenString);

        return new ActorAwareJwtToken(idTokenJwt, accessTokenJwt, remoteAddress, idProvider);

    }

    private TokenRequest buildTokenRequestFromForm(final Form form, final OidcProviderHandler oidcProviderHandler) {
        MultivaluedMap<String, String> formMap = form.asMap();
        log.trace("Request validated {}", formMap);
        final String clientId = formMap.get("client_id").get(0);
        Optional<OidcProviderInfo> oidcProviderInfoOpt = oidcProviderHandler.retrieveProviderInfoByClientId(clientId);
        if (oidcProviderInfoOpt.isEmpty()) {
            throw new ForbiddenException("Client Id is invalid");
        }
        OidcProviderInfo oidcProviderInfo = oidcProviderInfoOpt.get();
        OIDCProviderMetadata oidcProviderMetadata = oidcProviderInfo.getOidcProviderMetadata();

        // Assume these values are obtained during the authorization process
        String authorizationCode = formMap.get(AUTHORIZATION_CODE).get(0);
        String redirectUri = formMap.get(REDIRECT_URI).get(0);
        String codeVerifier = formMap.get(CODE_VERIFIER).get(0);

        // Construct the Authorization Code Grant with PKCE
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(
                new AuthorizationCode(authorizationCode),
                URI.create(redirectUri),
                new CodeVerifier(codeVerifier)
        );

        // Client ID obtained during client registration
        ClientID clientID = new ClientID(oidcProviderInfo.getClientId());
        Secret clientSecret = new Secret(oidcProviderInfo.getClientSecret());
        // With client secret
        ClientSecretBasic clientSecretBasic = new ClientSecretBasic(clientID, clientSecret);

        // Retrieve the token endpoint URI from OIDCProviderMetadata
        URI tokenEndpoint = oidcProviderMetadata.getTokenEndpointURI();

        return new TokenRequest(tokenEndpoint, clientSecretBasic, codeGrant);
    }

    private void validateForm(Form form) {
        MultivaluedMap<String, String> formMap = form.asMap();

        if (formMap.size() != 5) {
            throw new ForbiddenException("Form is malformed");
        }

        validateField(formMap, "grant_type", "grant_type is invalid");
        validateField(formMap, REDIRECT_URI, "redirect_uri is invalid");
        validateField(formMap, AUTHORIZATION_CODE, "code is invalid");
        validateField(formMap, CODE_VERIFIER, "code verifier is invalid");
        validateField(formMap, "client_id", "client Id is invalid");

        if (!"authorization_code".equals(formMap.get("grant_type").get(0))) {
            throw new ForbiddenException("grant_type is invalid");
        }

        if (!formMap.get(REDIRECT_URI).get(0).startsWith("https")) {
            throw new ForbiddenException("redirect_uri is invalid");
        }
    }

    private void validateField(MultivaluedMap<String, String> formMap, String fieldName, String errorMessage) {
        List<String> values = formMap.get(fieldName);
        if (values == null || values.size() != 1) {
            throw new ForbiddenException(errorMessage);
        }
    }


}
