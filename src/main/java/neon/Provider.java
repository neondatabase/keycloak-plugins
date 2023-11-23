package neon;

import neon.model.UserData;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;


import java.sql.*;

public class Provider implements
        UserStorageProvider,
        UserLookupProvider
{
    private final KeycloakSession session;
    private final ComponentModel model;
    private final Connection conn;

    public Provider(KeycloakSession session, ComponentModel model, Connection conn) {
        this.session = session;
        this.model = model;
        this.conn = conn;
    }

    @Override
    public void close() {
    }

    @Override
    public UserModel getUserById(RealmModel realm, String s) {
        System.out.println("GET BY ID");
        try {
            StorageId id = new StorageId(s);
            PreparedStatement stmt = conn.prepareStatement("select * from users where id = ?::uuid");
            stmt.setString(1, id.getExternalId());
            ResultSet results = stmt.executeQuery();

            // go to the first result- or, if there are no results, return null to indicate there is no such user
            if (!results.next()) {
                return null;
            }

            UserModel user = userFromResultSet(realm, results);

            // check for further results- if there are, throw an error
            if (results.next()) {
                throw new RuntimeException("multiple results from user lookup query");
            }

            return user;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String s) {
        System.out.println("GET BY EMAIL");
        try {
            PreparedStatement stmt = conn.prepareStatement("select * from users where email = ?");
            stmt.setString(1, s);
            ResultSet results = stmt.executeQuery();

            // go to the first result- or, if there are no results, return null to indicate there is no such user
            if (!results.next()) {
                return null;
            }

            UserModel user = userFromResultSet(realm, results);

            // check for further results- if there are, throw an error
            if (results.next()) {
                throw new RuntimeException("multiple results from user lookup query");
            }

            return user;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String s) {
        System.out.println("GET BY USERNAME");
        return getUserByEmail(realm, s); // usernames are emails in our system
    }
    
    private UserModel userFromResultSet(RealmModel realm, ResultSet results) throws SQLException {
        return new UserData(
            session, realm, model,

            results.getString("id"),
            results.getString("email"),
            results.getString("name"),
            results.getString("last_name"),
            results.getString("deleted_at") != null
        );
    }
}
