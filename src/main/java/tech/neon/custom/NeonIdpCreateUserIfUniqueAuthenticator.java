package tech.neon.custom;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.IdpEmailVerificationAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;

/**
 * Custom implementation of Keycloak's IdP user creation authenticator.
 * This authenticator functions similarly to the built-in IdpCreateUserIfUniqueAuthenticator,
 * but adds support for the VERIFIED_EMAIL flag set by NeonIdpEmailVerificationAuthenticator.
 */
public class NeonIdpCreateUserIfUniqueAuthenticator extends AbstractIdpAuthenticator {

    private static Logger logger = Logger.getLogger(NeonIdpCreateUserIfUniqueAuthenticator.class);

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
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        String email = brokerContext.getEmail();

        UserModel existingUser = context.getSession().users().getUserByEmail(context.getRealm(), email);

        if (existingUser == null) {
            logger.debugf(
                    "No duplication detected. Creating account for user '%s' and linking with identity provider '%s' .",
                    email, brokerContext.getIdpConfig().getAlias());

            UserModel federatedUser = session.users().addUser(realm, email);
            federatedUser.setEnabled(true);

            if (Boolean.TRUE.equals(brokerContext.getContextData().get(NeonIdpEmailVerificationAuthenticator.VERIFIED_EMAIL))) {
                federatedUser.setEmailVerified(true);
                logger.debug("Email verified successfully for user: " + federatedUser.getEmail());
            } else {
                federatedUser.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
            }

            for (Map.Entry<String, List<String>> attr : serializedCtx.getAttributes().entrySet().stream()
                    .sorted(Map.Entry.comparingByKey()).toList()) {
                if (!UserModel.USERNAME.equalsIgnoreCase(attr.getKey())) {
                    federatedUser.setAttribute(attr.getKey(), attr.getValue());
                }
            }

            context.setUser(federatedUser);
            context.getAuthenticationSession().setAuthNote(BROKER_REGISTERED_NEW_USER, "true");
            context.success();
        } else {
            ExistingUserInfo duplication = new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
            logger.debugf("Duplication detected. There is already existing user with %s '%s' .",
                    duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue());

            // Set duplicated user, so next authenticators can deal with it
            context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, duplication.serialize());
            context.attempted();
        }
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
    }

}