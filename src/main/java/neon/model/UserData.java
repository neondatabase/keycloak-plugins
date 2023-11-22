package neon.model;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.LegacyUserCredentialManager;
import org.keycloak.models.*;
import org.keycloak.storage.adapter.AbstractUserAdapter;


public class UserData extends AbstractUserAdapter implements UserModel {
    private final KeycloakSession session;
    private final RealmModel realm;

    private String id, email, firstName, lastName;

    public UserData(KeycloakSession session, RealmModel realm, ComponentModel model) {
        super(session, realm, model);
        this.session = session;
        this.realm = realm;
    }

    @Override
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getFirstName() {
        return firstName;
    }

    @Override
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    @Override
    public String getLastName() {
        return lastName;
    }

    @Override
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return new LegacyUserCredentialManager(session, realm, this);
    }
}
