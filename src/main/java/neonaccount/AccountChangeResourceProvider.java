package neonaccount;

import jakarta.ws.rs.core.UriInfo;
import neonaccount.updateemail.NeonUpdateEmailActionToken;
import org.jboss.logging.Logger;

import org.keycloak.authorization.util.Tokens;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.Auth;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.userprofile.UserProfileContext;

import java.util.concurrent.TimeUnit;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

public class AccountChangeResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final Auth auth;
    private final RealmModel realm;
    private final EventBuilder event;
    private final ClientModel client;
    private static final Logger logger = Logger.getLogger(AccountChangeResourceProvider.class);
    private static final int Timeout = 60 * 15;

    public AccountChangeResourceProvider(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();

        this.client = this.realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        if (client == null || !client.isEnabled()) {
            logger.debug("account management not enabled");
            throw new NotFoundException("account management not enabled");
        }
        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session)
                .setAudience(client.getClientId())
                .authenticate();

        if (authResult == null) {
            throw new NotAuthorizedException("Bearer token required");
        }

        this.auth = new Auth(this.realm, authResult.getToken(), authResult.getUser(), client, authResult.getSession(), false);
        this.event = new EventBuilder(realm, session, session.getContext().getConnection());
    }

    @Context
    private SecurityContext securityContext;

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }


    @PUT
    @Path("/update-user-email/{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateUserEmail(@PathParam("clientId") String clientId, String newEmail) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);
        event.event(EventType.UPDATE_EMAIL).detail(Details.CONTEXT, UserProfileContext.ACCOUNT.name());

        UserModel userFromToken = getUserFromToken(session);

        UserModel user = session.users().getUserById(realm, userFromToken.getId());
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("User not found").build();
        }

        NeonUpdateEmailActionToken actionToken = new NeonUpdateEmailActionToken(user.getId(),
                Time.currentTime() + Timeout,
                user.getEmail(), newEmail, clientId, true);

        UriInfo uriInfo = session.getContext().getUri();
        String link = Urls
                .actionTokenBuilder(uriInfo.getBaseUri(), actionToken.serialize(session, realm, uriInfo),
                        clientId, "")
                .build(realm.getName()).toString();

        try {
            session.getProvider(EmailTemplateProvider.class).setRealm(realm)
                    .setUser(user).sendEmailUpdateConfirmation(link, TimeUnit.SECONDS.toMinutes(Timeout), newEmail);
        } catch (EmailException e) {
            logger.error("Failed to send email for email update", e);
            event.event(EventType.UPDATE_EMAIL_ERROR).error(Errors.EMAIL_SEND_FAILED);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        return Response.ok().entity("Email sent successfully").build();
    }

    @PUT
    @Path("/update-user-password")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateUserPassword(String newPassword) {
        auth.require(AccountRoles.MANAGE_ACCOUNT);
        event.event(EventType.UPDATE_PASSWORD).detail(Details.CONTEXT, UserProfileContext.ACCOUNT.name());

        UserModel userFromToken = getUserFromToken(session);

        UserModel user = session.users().getUserById(realm, userFromToken.getId());
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("User not found").build();
        }

        try {
            user.credentialManager().updateCredential(UserCredentialModel.password(newPassword, false));
        } catch (Exception e) {
            logger.error("Failed to update user password", e);
            event.event(EventType.UPDATE_PASSWORD_ERROR).error(Errors.PASSWORD_REJECTED);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        return Response.ok().entity("Password updated successfully").build();
    }

    private UserModel getUserFromToken(KeycloakSession keycloakSession) {
        AccessToken accessToken = Tokens.getAccessToken(keycloakSession);
        if (accessToken.getSessionState() == null) {
            return TokenManager.lookupUserFromStatelessToken(keycloakSession, realm, accessToken);
        }

        UserSessionProvider sessions = keycloakSession.sessions();
        UserSessionModel userSession = sessions.getUserSession(realm, accessToken.getSessionState());

        if (userSession == null) {
            userSession = sessions.getOfflineUserSession(realm, accessToken.getSessionState());
        }

        return userSession.getUser();
    }
}