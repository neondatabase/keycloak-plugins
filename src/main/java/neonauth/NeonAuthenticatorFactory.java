package neonauth;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;


public class NeonAuthenticatorFactory implements AuthenticatorFactory {

    @Override
    public Authenticator create(KeycloakSession session) {
        return new NeonAuth();
    }

    @Override
    public void init(Scope config) {
        return;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        return;
    }

    @Override
    public void close() {
        return;
    }

    @Override
    public String getId() {
        return "neon-custom-auth-factory";
    }

    @Override
    public String getDisplayType() {
        return "neon-override-authentication";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[]{Requirement.REQUIRED};
    }

    @Override
    public boolean isUserSetupAllowed() {
       return true;
    }

    @Override
    public String getHelpText() {
        return "custom made neon authenticator to deal with unverified email signing with social login";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new ArrayList<>();
    }
    
}
