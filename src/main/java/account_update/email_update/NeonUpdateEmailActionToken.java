package account_update.email_update;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

// taken from keycloak UpdateEmailActionToken.java
// https://github.com/keycloak/keycloak/blob/66f0d2ff1db6f5ec442b0ddab4580bdd652d8877/services/src/main/java/org/keycloak/authentication/actiontoken/updateemail/UpdateEmailActionToken.java#L23
public class NeonUpdateEmailActionToken extends DefaultActionToken {

	public static final String TOKEN_TYPE = "update-email";

	@JsonProperty("oldEmail")
	private String oldEmail;
	@JsonProperty("newEmail")
	private String newEmail;
    @JsonProperty("logoutSessions")
    private Boolean logoutSessions;

	public NeonUpdateEmailActionToken(String userId, int absoluteExpirationInSecs, String oldEmail, String newEmail, String clientId, Boolean logoutSessions) {
		super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null);
		this.oldEmail = oldEmail;
		this.newEmail = newEmail;
		this.issuedFor = clientId;
        this.logoutSessions = Boolean.TRUE.equals(logoutSessions)? true : null;
	}

	private NeonUpdateEmailActionToken(){

	}

	public String getOldEmail() {
		return oldEmail;
	}

	public void setOldEmail(String oldEmail) {
		this.oldEmail = oldEmail;
	}

	public String getNewEmail() {
		return newEmail;
	}

	public void setNewEmail(String newEmail) {
		this.newEmail = newEmail;
	}

    public Boolean getLogoutSessions() {
        return this.logoutSessions;
    }

    public void setLogoutSessions(Boolean logoutSessions) {
        this.logoutSessions = Boolean.TRUE.equals(logoutSessions)? true : null;
    }
}
