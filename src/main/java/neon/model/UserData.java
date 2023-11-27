package neon.model;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.LegacyUserCredentialManager;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.LegacyStoreManagers;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;


public class UserData implements UserModel {
    private final KeycloakSession session;
    private final RealmModel realm;
    private final ComponentModel model;

    private final String id;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final boolean enabled;

    public UserData(
        KeycloakSession session, RealmModel realm, ComponentModel model,

        String id,
        String email,
        String firstName,
        String lastName,
        boolean enabled
    ) {
        this.session = session;
        this.realm = realm;
        this.model = model;
        this.id = id;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.enabled = enabled;
    }

    @Override
    public String getId() {
        return new StorageId(model.getId(), id).getId();
    }

    @Override
    public String getFirstName() {
        return firstName;
    }

    @Override
    public String getLastName() {
        return lastName;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public boolean isEmailVerified() {
        return false;
    }

    @Override
    public Long getCreatedTimestamp() {
        return null;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }



    @Override
    public String getFederationLink() {
        return null;
    }

    @Override
    public Stream<GroupModel> getGroupsStream() {
        return Stream.empty();
    }

    @Override
    public String getServiceAccountClientLink() {
        return null;
    }



    @Override
    public void setEmail(String email) {
        throw new ReadOnlyException();
    }

    @Override
    public void setEmailVerified(boolean verified) {
        throw new ReadOnlyException();
    }


    @Override
    public void joinGroup(GroupModel group) {
        throw new ReadOnlyException();
    }

    @Override
    public void leaveGroup(GroupModel group) {
        throw new ReadOnlyException();
    }

    @Override
    public boolean isMemberOf(GroupModel group) {
        return false;
    }



    @Override
    public void setFederationLink(String link) {
        throw new ReadOnlyException();
    }

    @Override
    public void setServiceAccountClientLink(String clientInternalId) {
        throw new ReadOnlyException();

    }

    @Override
    public void setUsername(String username) {
        throw new ReadOnlyException();

    }

    @Override
    public void setCreatedTimestamp(Long timestamp) {
        throw new ReadOnlyException();

    }

    @Override
    public void setFirstName(String firstName) {
        throw new ReadOnlyException();

    }

    @Override
    public void setLastName(String lastName) {
        throw new ReadOnlyException();

    }

    @Override
    public void setEnabled(boolean enabled) {
        throw new ReadOnlyException();
    }



    @Override
    public void setSingleAttribute(String name, String value) {
    }

    @Override
    public void setAttribute(String name, List<String> values) {
    }

    @Override
    public void removeAttribute(String name) {
    }

    @Override
    public String getFirstAttribute(String name) {
        return null;
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        return Stream.empty();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return new HashMap<>();
    }



    @Override
    public Stream<String> getRequiredActionsStream() {
        return Stream.empty();
    }

    @Override
    public void addRequiredAction(String action) {
        throw new ReadOnlyException();
    }

    @Override
    public void removeRequiredAction(String action) {
        throw new ReadOnlyException();
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return new LegacyUserCredentialManager(session, realm, this);
    }

    @Override
    public Stream<RoleModel> getRealmRoleMappingsStream() {
        return Stream.empty();
    }

    @Override
    public Stream<RoleModel> getClientRoleMappingsStream(ClientModel app) {
        return Stream.empty();
    }

    @Override
    public boolean hasRole(RoleModel role) {
        return false;
    }

    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        return Stream.empty();
    }

    @Override
    public void grantRole(RoleModel role) {
        throw new ReadOnlyException();
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        throw new ReadOnlyException();
    }
}
