package tech.neon.microsoft;

import org.keycloak.broker.oidc.mappers.UserAttributeMapper;

public class MicrosoftUserAttributeMapper extends UserAttributeMapper {

	private static final String[] cp = new String[] { MicrosoftIdentityProviderFactory.PROVIDER_ID };

	@Override
	public String[] getCompatibleProviders() {
		return cp;
	}

	@Override
	public String getId() {
		return "neonmicrosoft-user-attribute-mapper";
	}

}
