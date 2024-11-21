FROM openjdk:23
VOLUME /tmp
COPY target/gateway.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]