package vercel;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.*;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorPage;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class VercelMPIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
    private static final String BROKER_NONCE_PARAM = "BROKER_NONCE";

    private static final Logger logger = Logger.getLogger(VercelMPIdentityProvider.class);
    //private static final String AUTH_URL = "https://api.vercel.com/oauth/authorize";
    private static final String TOKEN_URL = "https://api.vercel.com/v1/integrations/sso/token";
    private static final String JWKS_URL = "https://marketplace.vercel.com/.well-known/jwks";
    private static final String ISSUER = "https://marketplace.vercel.com";

    public VercelMPIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);

        //config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setJwksUrl(JWKS_URL);
        config.setValidateSignature(true);
        config.setUseJwksUrl(true);
        config.setClientAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);
        config.setIssuer(ISSUER);
        config.setDisableNonce(true);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new VercelMPIdentityProvider.Endpoint(realm, callback, event, this);
    }

    @Override
    // Basically copy-paste from the parent class. With the following modifications:
    // * no need to verify Vercel access token here (and it doesn't provide it)
    // * do not check that identity ID extracted from ID token matches `sub` claim, because the `sub` claim looks like `account:XXX:user:XXXX`
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        AccessTokenResponse tokenResponse;
        try {
            tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not decode access token response.", e);
        }

        String encodedIdToken = tokenResponse.getIdToken();

        JsonWebToken idToken = validateToken(encodedIdToken);

        if (getConfig().isPassMaxAge()) {
            AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();

            if (isAuthTimeExpired(idToken, authSession)) {
                throw new IdentityBrokerException("User not re-authenticated by the target OpenID Provider");
            }

            Object authTime = idToken.getOtherClaims().get(IDToken.AUTH_TIME);

            if (authTime != null) {
                authSession.setClientNote(AuthenticationManager.AUTH_TIME_BROKER, authTime.toString());
            }
        }

        try {
            BrokeredIdentityContext identity = extractIdentity(tokenResponse, idToken);

            if (getConfig().isFilteredByClaims()) {
                String filterName = getConfig().getClaimFilterName();
                String filterValue = getConfig().getClaimFilterValue();

                logger.tracef("Filtering user %s by %s=%s", idToken.getOtherClaims().get(getusernameClaimNameForIdToken()), filterName, filterValue);
                if (idToken.getOtherClaims().containsKey(filterName)) {
                    Object claimObject = idToken.getOtherClaims().get(filterName);
                    List<String> claimValues = new ArrayList<>();
                    if (claimObject instanceof List) {
                        ((List<?>)claimObject).forEach(v->claimValues.add(Objects.toString(v)));
                    } else {
                        claimValues.add(Objects.toString(claimObject));
                    }
                    logger.tracef("Found claim %s with values %s", filterName, claimValues);
                    if (!claimValues.stream().anyMatch(v->v.matches(filterValue))) {
                        logger.warnf("Claim %s has values \"%s\" that does not match the expected filter \"%s\"", filterName, claimValues, filterValue);
                        throw new IdentityBrokerException(String.format("Unmatched claim value for %s.", filterName)).
                                withMessageCode(Messages.IDENTITY_PROVIDER_UNMATCHED_ESSENTIAL_CLAIM_ERROR);
                    }
                } else {
                    logger.debugf("Claim %s was not found", filterName);
                    throw new IdentityBrokerException(String.format("Claim %s not found", filterName)).
                            withMessageCode(Messages.IDENTITY_PROVIDER_UNMATCHED_ESSENTIAL_CLAIM_ERROR);
                }
            }

            if (!getConfig().isDisableNonce()) {
                identity.getContextData().put(BROKER_NONCE_PARAM, idToken.getOtherClaims().get(OIDCLoginProtocol.NONCE_PARAM));
            }

            if (getConfig().isStoreToken()) {
                if (tokenResponse.getExpiresIn() > 0) {
                    long accessTokenExpiration = Time.currentTime() + tokenResponse.getExpiresIn();
                    tokenResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                    response = JsonSerialization.writeValueAsString(tokenResponse);
                }
                identity.setToken(response);
            }

            return identity;
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not fetch attributes from userinfo endpoint.", e);
        }
    }

    // Extract user's identity from JWT.
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, JsonWebToken idToken) {
        // Global user ID is provided by Vercel only for Neon integrations!
        // For other marketplace integrations it provides only user ID per each integration installation.
        // I.e. the same Vercel user will have different ID in different Vercel teams.
        //
        // In case global_user_id is not set we will fall back to user ID per installation.
        String id = (String) idToken.getOtherClaims().get("global_user_id");
        if (id == null || id.isEmpty()) {
            id = (String) idToken.getOtherClaims().get("user_id");
        }

        BrokeredIdentityContext identity = new BrokeredIdentityContext(id, getConfig());

        String name = (String) idToken.getOtherClaims().get("user_name");
        String email = (String) idToken.getOtherClaims().get("user_email");

        if (email == null || email.isEmpty()) {
            email = id + "@vercel-marketplace.com";
        }

        identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);

        identity.setId(id);
        identity.setEmail(email);
        identity.setName(name);
        identity.setUsername((name == null || name.isEmpty()) ? email : name);

        identity.setBrokerUserId(getConfig().getAlias() + "." + id);

        if (tokenResponse != null && tokenResponse.getSessionState() != null) {
            identity.setBrokerSessionId(getConfig().getAlias() + "." + tokenResponse.getSessionState());
        }
        if (tokenResponse != null) identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
        if (tokenResponse != null) processAccessTokenResponse(identity, tokenResponse);

        return identity;
    }

    protected static class Endpoint extends OIDCEndpoint {
        private final VercelMPIdentityProvider provider;

        public Endpoint(RealmModel realm, AuthenticationCallback callback, EventBuilder event, VercelMPIdentityProvider provider) {
            super(callback, realm, event, provider);
            this.provider = provider;
        }

        @GET
        @Override
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error,
                                     @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {

            logger.info("Vercel authResponse call");

            OAuth2IdentityProviderConfig providerConfig = provider.getConfig();

            if (authorizationCode == null) {
                logErroneousRedirectUrlError("Redirection URL does not contain an authorization code",
                        providerConfig);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_CODE_OR_ERROR_ERROR);
            }

            if (state == null) {
                logErroneousRedirectUrlError("Redirection URL does not contain a state parameter", providerConfig);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
            }

            try {
                ClientModel client = realm.getClientByClientId("neon-console");

                RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, true);
                AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);

                KeycloakUriInfo uriInfo = session.getContext().getUri();
                authSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
                authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
                String redirectUri = client.getBaseUrl() + "/auth/keycloak/callback";
                authSession.setRedirectUri(redirectUri);
                authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);
                authSession.setClientNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, OAuth2Constants.CODE);
                authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()));

                session.getContext().setAuthenticationSession(authSession);

                SimpleHttp simpleHttp = generateTokenRequest(authorizationCode, state);
                String response;
                try (SimpleHttp.Response simpleResponse = simpleHttp.asResponse()) {
                    int status = simpleResponse.getStatus();
                    boolean success = status >= 200 && status < 400;
                    response = simpleResponse.asString();

                    if (!success) {
                        logger.errorf("Unexpected response from token endpoint %s. status=%s, response=%s",
                                simpleHttp.getUrl(), status, response);
                        return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }

                BrokeredIdentityContext federatedIdentity = provider.getFederatedIdentity(response);

                if (providerConfig.isStoreToken()) {
                    // make sure that token wasn't already set by getFederatedIdentity();
                    // want to be able to allow provider to set the token itself.
                    if (federatedIdentity.getToken() == null)federatedIdentity.setToken(response);
                }

                federatedIdentity.setIdp(provider);
                federatedIdentity.setAuthenticationSession(authSession);

                return callback.authenticated(federatedIdentity);
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (IdentityBrokerException e) {
                if (e.getMessageCode() != null) {
                    return errorIdentityProviderLogin(e.getMessageCode());
                }
                logger.error("Failed to make identity provider oauth callback", e);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
        }

        private Response errorIdentityProviderLogin(String message) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }

        private void logErroneousRedirectUrlError(String mainMessage, OAuth2IdentityProviderConfig providerConfig) {
            String providerId = providerConfig.getProviderId();
            String redirectionUrl = session.getContext().getUri().getRequestUri().toString();

            logger.errorf("%s. providerId=%s, redirectionUrl=%s", mainMessage, providerId, redirectionUrl);
        }

        // Vercel uses JSON request format instead of form-encoded.
        public SimpleHttp generateTokenRequest(String authorizationCode, String state) {
            OAuth2IdentityProviderConfig providerConfig = provider.getConfig();

            AccessTokenRequest accessTokenRequest = new AccessTokenRequest();
            accessTokenRequest.setCode(authorizationCode);
            accessTokenRequest.setState(state);
            try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(provider.getConfig().getClientSecret())) {
                accessTokenRequest.setClientSecret(vaultStringSecret.get().orElse(provider.getConfig().getClientSecret()));
                accessTokenRequest.setClientId(provider.getConfig().getClientId());
            }

            return SimpleHttp.doPost(providerConfig.getTokenUrl(), session)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .json(accessTokenRequest);
        }

        private static class AccessTokenRequest {

            @JsonProperty(OAUTH2_PARAMETER_CODE)
            private String code;

            @JsonProperty(OAUTH2_PARAMETER_STATE)
            private String state;

            @JsonProperty(OAUTH2_PARAMETER_CLIENT_SECRET)
            private String clientSecret;

            @JsonProperty(OAUTH2_PARAMETER_CLIENT_ID)
            private String clientId;

            public void setCode(String code) {
                this.code = code;
            }

            public String getCode() {
                return code;
            }

            public void setState(String state) {
                this.state = state;
            }

            public String getState() {
                return state;
            }

            public String getClientSecret() {
                return clientSecret;
            }

            public void setClientSecret(String clientSecret) {
                this.clientSecret = clientSecret;
            }

            public void setClientId(String clientId) {
                this.clientId = clientId;
            }

            public String getClientId() {
                return clientId;
            }
        }

    }
}
