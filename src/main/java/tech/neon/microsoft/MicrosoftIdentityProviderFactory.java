package tech.neon.microsoft;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.social.microsoft.MicrosoftIdentityProviderConfig;

public class MicrosoftIdentityProviderFactory extends AbstractIdentityProviderFactory<MicrosoftIdentityProvider> implements SocialIdentityProviderFactory<MicrosoftIdentityProvider> {

   public static final String PROVIDER_ID = "neon-microsoft";

   @Override
   public String getName() {
       return "Neon Microsoft";
   }

   @Override
   public MicrosoftIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
       return new MicrosoftIdentityProvider(session, new OIDCIdentityProviderConfig(model));
   }

   @Override
   public MicrosoftIdentityProviderConfig createConfig() {
       return new MicrosoftIdentityProviderConfig();
   }

   @Override
   public String getId() {
       return PROVIDER_ID;
   }
}