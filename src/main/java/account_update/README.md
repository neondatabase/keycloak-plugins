# Account update

Implements the RealmResourceProvider plugin.
We are using it to implement keycloak update-side of [change email feature](https://github.com/neondatabase/cloud/issues/4541),
basically extending the Keycloak [user access management API](https://keycloak.discourse.group/t/is-there-a-way-for-a-user-to-do-remove-an-optional-otp-configured/23382/2?u=adg92)
This plugin can be a possible contribution to Keycloak.

In Console, we use the Keycloak user access API for the change of first name, last name and identity provider links (social accounts).

The password change is not supported via the user access API, only via the Keycloak UI,
so we created the _update-user-password_ API to change the password using the users' access token.

### Email change
For email change we wanted the change to work the same as the UPDATE_EMAIL flow with a validation email that is being sent to the user.
The user access API changes the users' email without invoking the email validation flow.
In order to use the UPDATE_EMAIL flow we created the _update-user-email_ API - using the users' access token to send the verification to their new email.

Email change presents an added level of difficulty since the users email is also stored in Console and needs to be updated in the DB.
Unlike names change, that can be updated in Console at the same time we are changing Keycloak, email cannot be updated once the user requested it.
The UPDATE_EMAIL flow sends a validation email that - only after the user confirms the new email is theirs, the email changes.

Before [user profile refactor](https://github.com/neondatabase/cloud/pull/9701), we were "fixing" this by updating the users' details after they logged in again.
This created a broken flow, put the faith of the actual update in the hands of the user and caused stale value in the user profile page and other potential bugs seen as how the email is being used in other place.

It became more of an issue with user profile refactor because we would expose email change to all users (including social logins).

To fix this flow, we modified the UpdateEmailActionTokenHandler.
It relies heavily on the same logic that was developed for UPDATE_EMAIL, but in addition, updates Console users and auth_accounts tables.
This way, the Console values are being updated when the user click the email change confirmation link.
We can also use it in the future to store pending email change requests, etc.


## Usage

1. Console invokes _update-user-email_ and _update-user-password_ for user requested changes.

2. After the user clicks the email change confirmation link - NeonUpdateEmailActionTokenHandler is called.