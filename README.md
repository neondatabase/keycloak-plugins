## This project contains Java plugins for Keycloak also known as [SPIs](https://www.keycloak.org/docs/latest/server_development/index.html#_providers)

### Description
[neon user storage](src/main/java/neon) in the repo is the UserStorageProvider plugin. 
Using it we will be able to fetch users from console DB for Keycloak, instead of using the Keycloak DB.
We decided to not go with it for the [migration](https://github.com/neondatabase/cloud/pull/8389)

[neonauth](src/main/java/neonauth) is the Authenticator plugin. 
We are using it to deal with an [edge case bug](https://github.com/neondatabase/cloud/issues/9100) created after the identity providers [migration](https://github.com/neondatabase/cloud/pull/8389) to Keycloak was merged.
It will be introduced to console in [PR #9198](https://github.com/neondatabase/cloud/pull/9198).
The idea with this plugin is to remove the users password credentials and the need to verify their email if they were succesful in logging in and their email is not verified (something that will only be possible with the edge case unverified emails bug described above).

[neonaccount](src/main/java/neonaccount) is the RealmResourceProvider plugin.
We are using it to implement keycloak update-side of [change email feature](https://github.com/neondatabase/cloud/issues/4541),
basically extending the Keycloak [user access management API](https://keycloak.discourse.group/t/is-there-a-way-for-a-user-to-do-remove-an-optional-otp-configured/23382/2?u=adg92)
This plugin can be a possible contribution to Keycloak.

In Console, we use the user access API for the change of first name, last name and identity provider links (social accounts).

For email change we wanted the change to work the same as the UPDATE_EMAIL flow with a validation email that is being sent.
The user access API changes the users' email without invoking the email validation flow.
In order to use the UPDATE_EMAIL flow we created the _update-user-email_ API - using the users' access token to send the verification to their new email.

The password change is not supported via the user access API, only via the Keycloak UI,
so we created the _update-user-password_ API to change the password using the users' access token.

### Building and using in Keycloak
* We are using [maven](pom.xml) in order to build the plugins in this repo.
* Keycloak knows what plugin to use based on what is described in the [META-INF file](src/main/resources/META-INF/services)
* After stating relevant plugin to be used, run `mvn install`
* Copy the neon-provider.jar file created under target to cloud repo.
  `cp target/neon-provider.jar /Users/<username>/Git/cloud/keycloak/neon-provider.jar`
* Keycloak will be rebuilt using the jar file
* For staging,production simply commit the new neon-provider.jar file