#!/bin/bash

CONTAINER=$(docker ps -f name=cloud-keycloak-1 --quiet)
docker cp target/neon-plugins.jar ${CONTAINER}:/opt/keycloak/providers/
docker exec -it ${CONTAINER}  /bin/bash