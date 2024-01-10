package neonauth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

public class NeonAuth implements Authenticator {

    private static final Logger LOG = Logger.getLogger(NeonAuth.class);

    @Override
    public void close() {
        return;
    }

    @Override
    public void action(AuthenticationFlowContext arg0) {
        return;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.success();
        return;
    }



    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel arg1, UserModel arg2) {
       return false;
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession arg0, RealmModel arg1, UserModel user) {
        if (user.isEmailVerified()) {
            return;
        }

        LOG.info("Chaning required actions and reset password for user whose email is not verified. Email: " + user.getEmail());

        SubjectCredentialManager manager = user.credentialManager();

        // get password credential
        manager.getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE).forEach(c -> manager.removeStoredCredentialById(c.getId()));

        user.removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);

        user.setEmailVerified(true);
    }
}