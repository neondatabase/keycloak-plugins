package neonupdateemail;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import neon.model.UserData;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.actiontoken.updateemail.UpdateEmailActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.Templates;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.authentication.RequiredActionContextResult;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.userprofile.EventAuditingAttributeChangeListener;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;

//import javax.ws.rs.*;
//import javax.ws.rs.core.Context;
//import javax.ws.rs.core.MediaType;
//import javax.ws.rs.core.Response;
import java.util.concurrent.TimeUnit;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

public class EmailChangeResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private static final Logger logger = Logger.getLogger(EmailChangeResourceProvider.class);

    public EmailChangeResourceProvider(KeycloakSession session) {
        this.session = session;
    }


    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }


    @PUT
    @Path("/update-user-email/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateUserEmail(@PathParam("userId") String userId, String newEmail) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("User not found").build();
        }
        String clientId = "neon-console";


        UpdateEmailActionToken actionToken = new UpdateEmailActionToken(user.getId(),
                Time.currentTime() + 60 * 3600,
                user.getEmail(), newEmail, clientId, true);

        UriInfo uriInfo = session.getContext().getUri();
        String link = Urls
                .actionTokenBuilder(uriInfo.getBaseUri(), actionToken.serialize(session, realm, uriInfo),
                        clientId, "")

                .build(realm.getName()).toString();

        try {
            session.getProvider(EmailTemplateProvider.class).setRealm(realm)
                    .setUser(user).sendEmailUpdateConfirmation(link, TimeUnit.SECONDS.toMinutes(60 * 3600), newEmail);
        } catch (EmailException e) {
            logger.error("Failed to send email for email update", e);
//            context.getEvent().error(Errors.EMAIL_SEND_FAILED);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }


        // Send email to the new email address
        // Your email sending logic goes here

        // Update user's email address
//        user.setEmail(newEmail);
//        session.userCredentialManager().updateCredential(realm, user, UserCredentialModel.password(newEmail));

        return Response.ok().entity("Email sent successfully").build();
    }



//    private void sendEmailUpdateConfirmation(RequiredActionContext context, boolean logoutSessions) {
////        UserModel user = UserData(); context.getUser();
//        UserModel user = new UserData(
//                session, new RealmModel(), new ComponentModel(),
//
//                "4b000d2e-48ca-4ce4-aa7f-bcc2ee763533",
//                "old@neon.tech",
//                "test etst",
//                "last name test",
//                false
//        );
//        String oldEmail = "old@neon.tech";
//        String newEmail = "new@neon.tech";//context.getHttpRequest().getDecodedFormParameters().getFirst(UserModel.EMAIL);
//
//        RealmModel realm = context.getRealm();
//        int validityInSecs = realm.getActionTokenGeneratedByUserLifespan(UpdateEmailActionToken.TOKEN_TYPE);
//
//        UriInfo uriInfo = context.getUriInfo();
//        KeycloakSession session = context.getSession();
//        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
//
//        UpdateEmailActionToken actionToken = new UpdateEmailActionToken(user.getId(), Time.currentTime() + validityInSecs,
//                oldEmail, newEmail, authenticationSession.getClient().getClientId(), logoutSessions);
//
//        String link = Urls
//                .actionTokenBuilder(uriInfo.getBaseUri(), actionToken.serialize(session, realm, uriInfo),
//                        authenticationSession.getClient().getClientId(), authenticationSession.getTabId())
//
//                .build(realm.getName()).toString();
//
//        context.getEvent().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, newEmail);
//        try {
//            session.getProvider(EmailTemplateProvider.class).setAuthenticationSession(authenticationSession).setRealm(realm)
//                    .setUser(user).sendEmailUpdateConfirmation(link, TimeUnit.SECONDS.toMinutes(validityInSecs), newEmail);
//        } catch (EmailException e) {
//            logger.error("Failed to send email for email update", e);
//            context.getEvent().error(Errors.EMAIL_SEND_FAILED);
//            return;
//        }
//        context.getEvent().success();
//
//        LoginFormsProvider forms = context.form();
//        context.challenge(forms.setAttribute("messageHeader", forms.getMessage("emailUpdateConfirmationSentTitle"))
//                .setInfo("emailUpdateConfirmationSent", newEmail).createForm(Templates.getTemplate(LoginFormsPages.INFO)));
//    }

//    private void updateEmailWithoutConfirmation(RequiredActionContext context,
//                                                UserProfile emailUpdateValidationResult) {
//
//        updateEmailNow(context.getEvent(), context.getUser(), emailUpdateValidationResult);
//        context.success();
//    }

//    public static UserProfile validateEmailUpdate(KeycloakSession session, UserModel user, String newEmail) {
//        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
//        formData.putSingle(UserModel.USERNAME, user.getUsername());
//        formData.putSingle(UserModel.EMAIL, newEmail);
//        UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
//        UserProfile profile = profileProvider.create(UserProfileContext.UPDATE_EMAIL, formData, user);
//        profile.validate();
//        return profile;
//    }
//
//    public static void updateEmailNow(EventBuilder event, UserModel user, UserProfile emailUpdateValidationResult) {
//
//        String oldEmail = user.getEmail();
//        String newEmail = emailUpdateValidationResult.getAttributes().getFirst(UserModel.EMAIL);
//        event.event(EventType.UPDATE_EMAIL).detail(Details.PREVIOUS_EMAIL, oldEmail).detail(Details.UPDATED_EMAIL, newEmail);
//        emailUpdateValidationResult.update(false, new EventAuditingAttributeChangeListener(emailUpdateValidationResult, event));
//    }
}