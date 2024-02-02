package neonupdateemail;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class EmailChangeResourceProviderFactory implements RealmResourceProviderFactory {

    // This will result in a new sub path under an existing realm
    // eg. http://localhost:8088/auth/realms/realm-name/custom
    public static final String ID = "custom-email-update";

    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new EmailChangeResourceProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }

}