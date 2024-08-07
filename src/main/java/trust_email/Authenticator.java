package trust_email;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

public class Authenticator implements org.keycloak.authentication.Authenticator {

    private static final Logger LOG = Logger.getLogger(Authenticator.class);

    @Override
    public void close() {
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel model, UserModel user) {
        return false;
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel model, UserModel user) {
        if (user.isEmailVerified()) {
            return;
        }

        LOG.info("Changing required actions and reset password for user whose email is not verified. Email: " + user.getEmail());

        SubjectCredentialManager manager = user.credentialManager();

        // get password credential
        manager.getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE).forEach(c -> manager.removeStoredCredentialById(c.getId()));

        user.removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
        user.setEmailVerified(true);
    }
}
