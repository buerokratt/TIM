# TARA-integration module installation and configuration guide. 

# 0. Used variables description

* `${PROJECT_ROOT}` - root folder of the project

# 1. Dependencies

## 1.1 Postgres database

In order to run TIM you need Postgres database.

You can set one up using Docker from out [Third-party-components](https://github.com/buerokratt/Third-party-components) repository.

## 1.2 ID-log

In order to change the source code and compile outside Docker you'll need [ID-log](https://github.com/buerokratt/Java.commons/tree/public).

*Note!* You will not need it to run Docker.

# 2. Configuration

Spring Boot applications support externalized configuration through *.properties files.

Application configuration can be found here: `${PROJECT_ROOT}/src/main/resources/application.properties`.  

## 2.0 Use `security.allowlist.jwt` to define allowed participants to access TIM

If there are issues with Ruuter connection to TIM:  
Go to [src -> main -> resources -> application.properties](https://github.com/buerokratt/TIM/blob/main/src/main/resources/application.properties) & modify `security.allowlist.jwt` value to have container names and relevant service URL  
for example:  
`security.allowlist.jwt=ruuter-v1-public,ruuter-v1-private,ruuter-v2-private,ruuter-v2-public,dmapper,resql,tim,tim-postgresql,chat-widget,customer-service,127.0.0.1,::1`

## 2.1 Certificates generation

**Note!** This step is only required if you run TIM outside Docker. Skip to [Postgres configuration](#22-postgresql-configuration)

**Note!** Both keystore password and alias password should be the same.

### 2.1.1 Tomcat SSL support

Tomcat SSL certificate is generated in Docker with:

```
keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -keystore "keystore.jks" -validity 3650
```

* The generated keystore should be configured in the `application.properties`

### 2.1.2 Certificate for JWT signature

JWT certificate is generated in Docker with:

```
keytool -genkeypair -alias jwtsign -keyalg RSA -keysize 2048 -keystore "jwtkeystore.jks" -validity 3650
```

relevant configuration properties:

```
jwt-integration.signature.key-store=classpath:jwtkeystore.jks
jwt-integration.signature.key-store-password=ppjjpp
jwt-integration.signature.keyStoreType=JKS
jwt-integration.signature.keyAlias=jwtsign
```

### 2.1.3 Changing Keystore password

To change keystore password, update Dockerfile and configuration with new password.

## 2.2 Postgresql configuration

TIM requires connection to Postgres database to run.

### 2.2.1 Setup Postgres

Follow [Postgres](https://github.com/buerokratt/Third-party-components/tree/main/Postgres) setup instructions.

### 2.2.2 Update properties

Update `application.properties` with following properties to match your Postgres configuration.

```
spring.datasource.url=jdbc:postgresql://localhost:9876/tim
spring.datasource.username=tim
spring.datasource.password=123
```

# 3. Running in Docker

Run docker with `docker-compose up -d`

**Note!** Some configuration changes may require you to rebuild docker image using `docker-compose build` for them to take effect.

# 4. Running tests

This requires a local JDK 17+ and [ID-log](https://github.com/buerokratt/Java.commons/tree/public) installed
(see [1.2 ID-log](#12-id-log)). If your local setup doesn't match, run the tests in Docker instead - no
local JDK or ID-log install required:

```
docker build -f Dockerfile.test .
```

This builds the project and runs the full test suite (including a JaCoCo coverage report) inside a
container matching the project's JDK version, and fails the build (non-zero exit code) if any test
fails. It doesn't produce a runnable image - it's a test gate, not a deployment artifact.

## Licence

See licence [here](LICENSE).
