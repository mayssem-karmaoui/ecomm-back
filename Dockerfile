#base image
FROM openjdk:17-jdk-alpine

#container working directory
WORKDIR /app

#copy package file
COPY target/*.jar app.jar

EXPOSE 8000

# Define the command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]