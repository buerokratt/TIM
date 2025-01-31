FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /workspace/app

ARG ID_LOG_VERSION=1.0.0-SNAPSHOT

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src
COPY libs libs

RUN ./mvnw install:install-file -Dfile=libs/id-log-${ID_LOG_VERSION}.jar \
    -DgroupId=ee.ria.commons -DartifactId=id-log -Dversion=${ID_LOG_VERSION} \
    -Dpackaging=jar -DgeneratePom=true && ./mvnw package -DskipTests=true

COPY generate-keystore.sh /workspace/app/
RUN chmod +x /workspace/app/generate-keystore.sh

ENTRYPOINT ["/bin/sh", "-c", "./generate-keystore.sh"]
