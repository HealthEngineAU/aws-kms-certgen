FROM maven:3-openjdk-11

WORKDIR /app

CMD ["mvn", "verify"]
