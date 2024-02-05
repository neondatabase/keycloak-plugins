# Trust Email

If a user attempts to sign up with email+password, does not verify their email,
and subsequently decides to sign up with an IDP using the same email instead,
by default they will be refused access until they have performed the email
verification action

To streamline the user signup experience, this plugin provides an auth flow step
which automatically sets the email as validated, and clears any email validation
action

This step will also delete any previously set passwords, otherwise malicious 
users could start registration with other user's email, set a password, wait 
for the real owner of that email to sign up with IDP, and then access the other
user's account with this password. Deleting passwords on execution of this step
prevents this type of vulnerability

## Usage

This step should be added to the `first broker login` flow, after the necessary
IDP authorisations steps have succeeded