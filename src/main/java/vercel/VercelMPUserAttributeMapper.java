package vercel;

import org.keycloak.broker.oidc.mappers.UserAttributeMapper;

/**
 * User attribute mapper.
 *
 */
public class VercelMPUserAttributeMapper extends UserAttributeMapper {

	private static final String[] cp = new String[] { VercelMPIdentityProviderFactory.PROVIDER_ID };

	@Override
	public String[] getCompatibleProviders() {
		return cp;
	}

	@Override
	public String getId() {
		return "vercelmp-user-attribute-mapper";
	}

}
