# Keycloak Plugins

Custom Java plugins for Keycloak:
- [Trust Email](src/main/java/trust_email/README.md)

Documentation on how to create Keycloak plugins can be found in the 
[Keycloak SPIs][1]

## Build

Ensure you have the Maven build command `mvn` installed. An IDE such as Intellij 

may provide this for you automatically

Run the following command:
```shell
mvn install
```

The output JAR can be found in the generated `target` directory

## Install

To use these plugins, copy the output JAR into the `opt/keycloak/providers` directory
of your Keycloak installation

If using a docker file, it is recommended to download the JAR directly from the
latest release of this repository from GitHub within a multistage build like so:
```dockerfile
FROM alpine AS neon-plugins

RUN wget https://github.com/neondatabase/keycloak-plugins/releases/download/<VERSION>/neon-plugins.jar

...

COPY --from=neon-plugins /neon-plugins.jar /opt/keycloak/providers/
```
replacing the `<VERSION>` as appropriate 

## Release

Updated versions of these plugins should be shared via GitHub Releases

you must include the compiled JAR file in the release artifacts, as dependent
projects are expected to download this directly from GitHub as part of their 
build pipeline


[1]: https://www.keycloak.org/docs/latest/server_development/index.html#_providers