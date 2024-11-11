package tech.neon.custom;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.IdpEmailVerificationAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import org.jboss.logging.Logger;

public class NeonIdpEmailVerifyAuthenticator extends AbstractIdpAuthenticator {
    public static final String VERIFIED_EMAIL = "VERIFIED_EMAIL";
    private static Logger logger = Logger.getLogger(IdpEmailVerificationAuthenticator.class);

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
        logger.debug("Starting email verification authentication for user: " + brokerContext.getEmail());

        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (brokerContext.getIdpConfig().isTrustEmail()
                || Boolean.TRUE.equals(brokerContext.getContextData().get(VERIFIED_EMAIL))) {
            logger.debug("Email is trusted or already verified. Proceeding with authentication.");

            UserModel user = getExistingUser(session, realm, authSession);
            user.setEmailVerified(true);
            logger.debug("Email verified successfully for user: " + user.getEmail());
            context.success();

        } else {
            logger.debug("Email verification attempted but not trusted/verified for: " + brokerContext.getEmail());
            context.attempted();
        }
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
        logger.warn("Action implementation called for email verification");
    }

}