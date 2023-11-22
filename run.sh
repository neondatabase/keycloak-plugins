#!/bin/bash

CONTAINER=$(docker ps -f name=cloud-keycloak-1 --quiet)
docker cp target/neon-provider.jar ${CONTAINER}:/opt/keycloak/providers/neon-provider.jar
docker exec -it ${CONTAINER} /bin/bash ./opt/keycloak/bin/kc.sh build