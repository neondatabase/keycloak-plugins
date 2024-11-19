package tech.neon.custom;

import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.sessions.AuthenticationSessionModel;

public class NeonCleanUnverifiedAuthenticator extends AbstractIdpAuthenticator {
    private static Logger logger = Logger.getLogger(NeonCleanUnverifiedAuthenticator.class);
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
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        UserModel user = getExistingUser(session, realm, authSession);

        if (user.isEmailVerified()) {
            logger.debug("User " + user.getUsername() + " is already verified, skipping cleanup");
            context.success();
            return;
        }

        logger.debug("Cleaning up unverified user: " + user.getUsername());
        SubjectCredentialManager manager = user.credentialManager();

        manager.getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE)
                .forEach(c -> {
                    logger.debug("Removing credential: " + c.getId() + " for user: " + user.getUsername());
                    manager.removeStoredCredentialById(c.getId());
                });

        session.users().getFederatedIdentitiesStream(realm, user).forEach(identity -> {
            logger.debug("Removing federated identity: " + identity.getIdentityProvider() + " for user: " + user.getUsername());
            session.users().removeFederatedIdentity(realm, user, identity.getIdentityProvider());
        });

        context.success();
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {

    }
}
