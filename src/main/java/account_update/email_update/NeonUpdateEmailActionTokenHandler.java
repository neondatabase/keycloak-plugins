package account_update.email_update;

import jakarta.ws.rs.core.Response;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.TokenUtils;
import org.keycloak.authentication.requiredactions.UpdateEmail;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.ValidationException;

import java.sql.*;
import java.util.List;
import java.util.Objects;
import java.net.URI;
import java.net.URISyntaxException;

// modified from UpdateEmailActionTokenHandler
// https://github.com/keycloak/keycloak/blob/66f0d2ff1db6f5ec442b0ddab4580bdd652d8877/services/src/main/java/org/keycloak/authentication/actiontoken/updateemail/UpdateEmailActionTokenHandler.java
public class NeonUpdateEmailActionTokenHandler extends AbstractActionTokenHandler<NeonUpdateEmailActionToken> {

    private final Connection conn;

    public NeonUpdateEmailActionTokenHandler() {
        super(NeonUpdateEmailActionToken.TOKEN_TYPE, NeonUpdateEmailActionToken.class, Messages.STALE_VERIFY_EMAIL_LINK,
                EventType.EXECUTE_ACTIONS, Errors.INVALID_TOKEN);

        String connectionString = System.getenv("CONSOLE_DB_URL");
        try {
            conn = DriverManager.getConnection(connectionString);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public TokenVerifier.Predicate<? super NeonUpdateEmailActionToken>[] getVerifiers(
            ActionTokenContext<NeonUpdateEmailActionToken> tokenContext) {
        return TokenUtils.predicates(TokenUtils.checkThat(
                t -> Objects.equals(t.getOldEmail(), tokenContext.getAuthenticationSession().getAuthenticatedUser().getEmail()),
                Errors.INVALID_EMAIL, getDefaultErrorMessage()));
    }

    @Override
    public Response handleToken(NeonUpdateEmailActionToken token, ActionTokenContext<NeonUpdateEmailActionToken> tokenContext) {
        AuthenticationSessionModel authenticationSession = tokenContext.getAuthenticationSession();
        UserModel user = authenticationSession.getAuthenticatedUser();

        KeycloakSession session = tokenContext.getSession();

        LoginFormsProvider forms = session.getProvider(LoginFormsProvider.class).setAuthenticationSession(authenticationSession)
                .setUser(user);

        String newEmail = token.getNewEmail();

        UserProfile emailUpdateValidationResult;
        try {
            emailUpdateValidationResult = UpdateEmail.validateEmailUpdate(session, user, newEmail);
        } catch (ValidationException pve) {
            List<FormMessage> errors = Validation.getFormErrorsFromValidation(pve.getErrors());
            return forms.setErrors(errors).createErrorPage(Response.Status.BAD_REQUEST);
        }

        UpdateEmail.updateEmailNow(tokenContext.getEvent(), user, emailUpdateValidationResult);

        if (Boolean.TRUE.equals(token.getLogoutSessions())) {
            AuthenticatorUtil.logoutOtherSessions(tokenContext);
        }

        tokenContext.getEvent().success();

        // verify user email as we know it is valid as this entry point would never have gotten here.
        user.setEmailVerified(true);
        user.removeRequiredAction(UserModel.RequiredAction.UPDATE_EMAIL);
        tokenContext.getAuthenticationSession().removeRequiredAction(UserModel.RequiredAction.UPDATE_EMAIL);
        user.removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
        tokenContext.getAuthenticationSession().removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);

        // unlink all social providers links from Keycloak
        RealmModel realm = session.getContext().getRealm();
        session.users().getFederatedIdentitiesStream(realm, user).
                forEach(link -> session.users().removeFederatedIdentity(realm, user, link.getIdentityProvider()));

        // updating console database users and auth_accounts tables
        try {
            PreparedStatement getStmt = conn.prepareStatement("select user_id from auth_accounts WHERE provider_uid = ?");
            getStmt.setString(1, user.getId());
            ResultSet results = getStmt.executeQuery();

            String consoleUserId = "";
            if (results.next()) {
                consoleUserId = results.getString("user_id");

                PreparedStatement stmt = conn.prepareStatement("BEGIN; UPDATE auth_accounts SET email = ? WHERE provider_uid = ?;" +
                        "UPDATE users SET email = ? WHERE id::text = ?; END");
                stmt.setString(1, newEmail);
                stmt.setString(2, user.getId());
                stmt.setString(3, newEmail);
                stmt.setString(4, consoleUserId);

                stmt.execute();

                // unlink all social providers from auth_accounts (in case the user linked again after changing email and before validating email)
                PreparedStatement removeSocialLinks = conn.prepareStatement("DELETE from auth_accounts WHERE user_id::text = ? AND provider != 'keycloak'");
                removeSocialLinks.setString(1, consoleUserId);

                removeSocialLinks.executeQuery();
            }
        } catch (SQLException e) {
            System.out.println("ERROR updating console database after email change for keycloak user " + user.getId());
            System.out.println("exception " + e);
        }

        return forms.setAttribute("messageHeader", forms.getMessage("emailUpdatedTitle")).setSuccess("emailUpdated", newEmail)
                .createInfoPage();
    }

    @Override
    public boolean canUseTokenRepeatedly(NeonUpdateEmailActionToken token,
                                         ActionTokenContext<NeonUpdateEmailActionToken> tokenContext) {
        return false;
    }
}
