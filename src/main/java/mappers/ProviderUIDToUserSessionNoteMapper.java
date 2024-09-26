package mappers;

import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;

public class ProviderUIDToUserSessionNoteMapper extends AbstractClaimMapper {

    private static final String[] COMPATIBLE_PROVIDERS = {IdentityProviderMapper.ANY_PROVIDER};

    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES =
            new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    public static final String PROVIDER_ID = "neon-idp-uid-user-session-note-mapper";

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "User Session";
    }

    @Override
    public String getDisplayType() {
        return "Provider UID to User Session Note Mapper";
    }

    @Override
    public String getHelpText() {
        return "Add identity_provider_uid to the user session notes.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        addClaimsToSessionNote(context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        addClaimsToSessionNote(context);
    }

    private void addClaimsToSessionNote(BrokeredIdentityContext context) {
        context.setSessionNote("identity_provider_uid", context.getId());
    }
}
