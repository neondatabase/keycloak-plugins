package neon;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class ProviderFactory implements UserStorageProviderFactory<Provider> {
    private Connection conn;

    @Override
    public String getId() {
        return "neon-user-provider";
    }

    @Override
    public void init(Config.Scope config) {
        // get db connection
        try {
            conn = DriverManager.getConnection(System.getenv("NEON_CONSOLE_DATABASE"));
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        // validate db schema or throw err
    }

    @Override
    public Provider create(KeycloakSession session, ComponentModel model) {
        return new Provider(session, model, conn);
    }

}
