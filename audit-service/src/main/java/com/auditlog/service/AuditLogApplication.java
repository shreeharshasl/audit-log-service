package com.auditlog.service;

import org.slf4j.bridge.SLF4JBridgeHandler;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuditLogApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuditLogApplication.class, args);
        // Tomcat logs 404s through java.util.logging. Spring Boot bridges JUL into Logback, and
        // on a fat-jar classloader that path cannot load ThrowableProxy — the request thread dies
        // and the browser hangs. Uninstalling the bridge after start keeps Tomcat's own JUL
        // handlers, so unknown URLs return instead of blocking forever.
        SLF4JBridgeHandler.uninstall();
    }
}
