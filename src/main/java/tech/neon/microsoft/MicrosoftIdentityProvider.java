package tech.neon.microsoft;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;

import tech.neon.custom.NeonIdpEmailVerificationAuthenticator;

import java.io.IOException;
import java.util.Map;

public class MicrosoftIdentityProvider extends OIDCIdentityProvider
        implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    private static final String AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"; // authorization
                                                                                                             // code
                                                                                                             // endpoint
    private static final String TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"; // token
                                                                                                          // endpoint
    private static final String DEFAULT_SCOPE = "openid profile email User.read"; // the User.read scope should be
                                                                                  // sufficient to obtain all necessary
                                                                                  // user info

    private static final String PROFILE_URL = "https://graph.microsoft.com/v1.0/me/"; // user profile service endpoint
    private static final Logger logger = Logger.getLogger(MicrosoftIdentityProvider.class);

    public MicrosoftIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);

        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {

        AccessTokenResponse tokenResponse = null;
        try {
            tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not decode access token response.", e);
        }

        JsonNode profile;
        try {
            profile = SimpleHttp.doGet(PROFILE_URL, session).auth(tokenResponse.getToken()).asJson();
            if (profile.has("error") && !profile.get("error").isNull()) {
                throw new IdentityBrokerException("Error in Microsoft Graph API response. Payload: " + profile.toString());
            }
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from Microsoft Graph", e);
        }

        String encodedIdToken = tokenResponse.getIdToken();

        JsonWebToken idToken = validateToken(encodedIdToken);

        Map<String, Object> claims = idToken.getOtherClaims();
        String id = (String) claims.get("oid");
        BrokeredIdentityContext identity = new BrokeredIdentityContext(id, getConfig());

        String email = (String) claims.get("email");
        String profileEmail = getJsonProperty(profile, "mail");
        
        if (email != null) {
            identity.setEmail(email);
            identity.getContextData().put(NeonIdpEmailVerificationAuthenticator.VERIFIED_EMAIL, true);
            logger.debug("Using verified email: " + email);
        } else if (profileEmail != null) {
            identity.setEmail(profileEmail);
            logger.info("Using unverified email: " + profileEmail);
        } else {
            String upnEmail = (String) claims.get("upn");
            identity.setEmail(upnEmail);
            identity.getContextData().put(NeonIdpEmailVerificationAuthenticator.VERIFIED_EMAIL, true);
            logger.debug("Email not found in claims and profile, using UPN instead: " + upnEmail);
        }
        identity.setUsername(id);

        identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);

        identity.setFirstName((String) claims.get("given_name"));
        identity.setLastName((String) claims.get("family_name"));

        identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
        processAccessTokenResponse(identity, tokenResponse);

        identity.getContextData().put("BROKER_NONCE", idToken.getOtherClaims().get(OIDCLoginProtocol.NONCE_PARAM));

        if (getConfig().isStoreToken()) {
            if (tokenResponse.getExpiresIn() > 0) {
                long accessTokenExpiration = Time.currentTime() + tokenResponse.getExpiresIn();
                tokenResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                try {
                    response = JsonSerialization.writeValueAsString(tokenResponse);
                } catch (IOException e) {
                    throw new IdentityBrokerException("JsonSerialization exception", e);
                }
            }
            identity.setToken(response);
        }

        return identity;
    }
}
