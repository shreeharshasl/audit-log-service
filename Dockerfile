# syntax=docker/dockerfile:1

# Build from the repo root. The service and the verifier both need audit-hashing-core,
# so the image is produced from the Maven reactor rather than a single module directory.
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /src

COPY pom.xml .
COPY config/spotbugs-exclude.xml config/spotbugs-exclude.xml
COPY audit-hashing-core/pom.xml audit-hashing-core/pom.xml
COPY audit-service/pom.xml audit-service/pom.xml
COPY audit-verifier-cli/pom.xml audit-verifier-cli/pom.xml

COPY audit-hashing-core audit-hashing-core
COPY audit-service audit-service
COPY audit-verifier-cli audit-verifier-cli

RUN --mount=type=cache,target=/root/.m2 \
    mvn -pl audit-service,audit-verifier-cli -am package -DskipTests -B

FROM eclipse-temurin:21-jre AS audit-service
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/audit-service/target/audit-service-*-SNAPSHOT.jar /app/app.jar
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=12 \
    CMD curl -fsS http://127.0.0.1:8080/audit-service/api/actuator/health
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

FROM eclipse-temurin:21-jre AS verifier
WORKDIR /app
COPY --from=build /src/audit-verifier-cli/target/audit-verifier.jar /app/audit-verifier.jar
ENTRYPOINT ["java", "-jar", "/app/audit-verifier.jar"]
