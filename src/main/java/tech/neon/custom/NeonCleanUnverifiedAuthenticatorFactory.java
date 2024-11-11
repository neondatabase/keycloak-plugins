package tech.neon.custom;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class NeonCleanUnverifiedAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "neon-clean-unverified";
    static NeonCleanUnverifiedAuthenticator SINGLETON = new NeonCleanUnverifiedAuthenticator();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
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
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] { 
            AuthenticationExecutionModel.Requirement.REQUIRED 
        };
    }

    @Override
    public String getDisplayType() {
        return "Clean Unverified User";
    }

    @Override
    public String getHelpText() {
        return "Cleans up unverified user data by removing passwords and social links";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
} 