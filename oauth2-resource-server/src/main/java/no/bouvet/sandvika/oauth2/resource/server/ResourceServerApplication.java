package no.bouvet.sandvika.oauth2.resource.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@SpringBootApplication
public class ResourceServerApplication
{
    public static void main(String[] args)
    {
        SpringApplication.run(ResourceServerApplication.class, args);
    }
}
