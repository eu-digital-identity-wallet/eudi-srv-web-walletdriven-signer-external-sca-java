# 1. Pulling the dependencies
FROM maven:3.8.5-eclipse-temurin-17 AS java_builder
# Change working directory in the container
WORKDIR /opt/app
COPY pom.xml .
COPY src ./src

# compile code in /opt/app
RUN mvn -B -e clean install

# 3. Preparing the runtime environment
FROM eclipse-temurin:17 AS java_runtime

WORKDIR /opt/app

# Start authorization_server
COPY --from=java_builder /opt/app/target/*.jar sca.jar

EXPOSE 8086
ENTRYPOINT ["java", "-jar", "sca.jar"]