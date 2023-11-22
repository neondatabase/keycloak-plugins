package neon;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.sql.Connection;

/**
 * Hello world!
 *
 */
public class Provider implements
        UserStorageProvider,
        UserLookupProvider
{

    private final Connection conn;

    public Provider(Connection conn) {
        this.conn = conn;
    }

    @Override
    public void close() {
    }

    @Override
    public UserModel getUserById(RealmModel realmModel, String s) {
        return null;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realmModel, String s) {
        return getUserByEmail(realmModel, s); // usernames are emails in our system
    }

    @Override
    public UserModel getUserByEmail(RealmModel realmModel, String s) {
        return null;
    }
}
