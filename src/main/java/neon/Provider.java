package neon;

import neon.model.UserData;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.sql.*;

/**
 * Hello world!
 *
 */
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
        try {
            PreparedStatement stmt = conn.prepareStatement("select * from users where id = ?");
            stmt.setString(1, s);

            return userFromResultSet(realm, stmt.executeQuery());
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String s) {
        try {
            PreparedStatement stmt = conn.prepareStatement("select * from users where email = ?");
            stmt.setString(1, s);

            return userFromResultSet(realm, stmt.executeQuery());
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String s) {
        return getUserByEmail(realm, s); // usernames are emails in our system
    }
    
    private UserModel userFromResultSet(RealmModel realm, ResultSet results) throws SQLException {
        if (!results.next()) {
            return null;
        }

        UserData user = new UserData(session, realm, model);

        user.setId(results.getString("id"));
        user.setEmail(results.getString("email"));
        user.setFirstName(results.getString("name"));
        user.setLastName(results.getString("last_name"));

        if (results.next()) {
            throw new RuntimeException("multiple results from user lookup query");
        }

        return user;
    }
}
