# JRE em vez do JDK completo: imagem menor e menos pacotes para o Trivy
# apontar como vulneráveis
FROM eclipse-temurin:25-jre

# não roda como root (Trivy/Dockerfile best practice)
RUN groupadd --system spring && useradd --system --gid spring --uid 1001 spring

COPY target/*.jar /app.jar

USER 1001
EXPOSE 8080

# respeita o limite de memória do container (k8s/compose)
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75"

ENTRYPOINT ["java", "-jar", "/app.jar"]
