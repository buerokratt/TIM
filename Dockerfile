FROM openjdk:11-jdk as build

WORKDIR /workspace/app

ARG ID_LOG_VERSION=1.0.0-SNAPSHOT
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src
COPY libs libs
RUN ./mvnw install:install-file -Dfile=libs/id-log-${ID_LOG_VERSION}.jar -DgroupId=ee.ria.commons -DartifactId=id-log -Dversion=${ID_LOG_VERSION} -Dpackaging=jar -DgeneratePom=true

# keytool 
ARG KEY_PASS="ppjjpp"
RUN keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -keystore "keystore.jks" -dname "CN=, OU=, O=, L=, ST=, C=" -storepass KEY_PASS -validity 3650
RUN keytool -genkeypair -alias jwtsign -keyalg RSA -keysize 2048 -keystore "jwtkeystore.jks" -dname "CN=, OU=, O=, L=, ST=, C=" -storepass KEY_PASS -validity 3650
RUN ./mvnw install -DskipTests

ENTRYPOINT ["java", "-jar", "./target/tim.war"]
