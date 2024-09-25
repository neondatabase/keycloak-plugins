package vercel;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class VercelMPIdentityProviderFactory extends AbstractIdentityProviderFactory<VercelMPIdentityProvider> implements SocialIdentityProviderFactory<VercelMPIdentityProvider> {

    public static final String PROVIDER_ID = "vercelmp";

    @Override
    public String getName() {
        return "Vercel MP";
    }

    @Override
    public VercelMPIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new VercelMPIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }

    @Override
    public OIDCIdentityProviderConfig createConfig() {
        return new OIDCIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
