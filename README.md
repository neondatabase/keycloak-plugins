## This project contains Java plugins for Keycloak also known as [SPIs](https://www.keycloak.org/docs/latest/server_development/index.html#_providers)

### Description
[neon user storage](src/main/java/neon) in the repo is the UserStorageProvider plugin. 
Using it we will be able to fetch users from console DB for Keycloak, instead of using the Keycloak DB.
We decided to not go with it for the [migration](https://github.com/neondatabase/cloud/pull/8389)

[neonauth](src/main/java/neonauth) is the Authenticator plugin. 
We are using it to deal with an [edge case bug](https://github.com/neondatabase/cloud/issues/9100) created after the identity providers [migration](https://github.com/neondatabase/cloud/pull/8389) to Keycloak was merged.
It will be introduced to console in [PR #9198](https://github.com/neondatabase/cloud/pull/9198).
The idea with this plugin is to remove the users password credentials and the need to verify their email if they were succesful in logging in and their email is not verified (something that will only be possible with the edge case unverified emails bug described above).

### Building and using in Keycloak
* We are using [maven](pom.xml) in order to build the plugins in this repo.
* Keycloak knows what plugin to use based on what is described in the [META-INF file](src/main/resources/META-INF/services)
* After stating relevant plugin to be used, run `mvn install`
* Copy the neon-provider.jar file created under target to cloud repo.
  `cp target/neon-provider.jar /Users/<username>/Git/cloud/keycloak/neon-provider.jar`
* Keycloak will be rebuilt using the jar file
* For staging,production simply commit the new neon-provider.jar file