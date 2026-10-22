export SPRING_PROFILES_ACTIVE=dev
mvn clean install
nohup java -jar target/sca-0.0.1-SNAPSHOT.jar > nohup_SCA.out 2>&1 &