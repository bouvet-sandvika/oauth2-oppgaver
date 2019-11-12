# Oppgaver til Workshop

### Oppgave 0 - benytte en eksisterende provider
Spring Security OAuth kan konfigureres til å benytte eksterne OAuth 2.0 providere som facebook, google eller github. I dette eksempelet skal vi benytte GitHub som en single sign-on (SSO) provider.

Første steg for å komme i gang er å registrere din applikasjon hos GitHub. Vi har allerede registrert en applikasjon for denne workshopen, men ønsker du opprette din egen kan du gjøre det her: https://github.com/settings/applications/new.

| Property | Verdi | beskrivelse | 
| -------- | ----- | ----------- |
| clientId | 7121fb82e7b5cef0552b | **Påkrevd felt.** Unik ID for applikasjonen levert av GitHub ved registrering.  | 
| clientSecret | <sendes på slack> | **Påkrevd felt.** En secret levert av GitHub ved registrering (PS: ikke commit denne) | 
| userAuthorizationUri | https://github.com/login/oauth/authorize | Benyttes for autentisering av brukeren. | 
| accessTokenUri | https://github.com/login/oauth/access_token | Uri som benyttes for å hente access token. | 
| clientAuthenticationScheme | form | Styrer hvordan klienten skal autentiseres mot OAuth 2.0 provideren (none, form, header, query). | 
| userInfoUri | https://api.github.com/user | Uri benyttes for å hente brukerinformasjon | 

For mer informasjon se GitHub sin utviklingsguide her: https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/

#### 0.0 Konfigurer Spring Security OAuth2
Spring Security OAuth2 konfigureres i ```application.yaml```. 

Gitt informasjonen i innledningen og [Spring Security Reference dok](https://docs.spring.io/spring-security-oauth2-boot/docs/current/reference/htmlsingle/#boot-features-security-custom-user-info-client), konfigurer Spring til å benytte GitHub som OAuth2 provider.

```yaml
server:
  port: 9292

security:
  oauth2:
    # Konfig legges inn her..
```

#### 0.1 Enable SSO
```@EnableOAuth2Sso``` enabler single sign-on for spring boot. Annotasjonen kan benyttes stand alone på en hvilken som helst configuration eller på en ```WebSecurityConfigurerAdapter```. 
Merk at hvis den benyttes stand alone vil alle stier til applikasjonen være sikret by default. For mer informasjon se [Spring Security Reference dok](https://docs.spring.io/spring-security-oauth2-boot/docs/current/reference/htmlsingle/#boot-features-security-oauth2-single-sign-on).

Benytt ```@EnableOAuth2Sso``` til sikre applikasjonen.

#### 0.2 First run
Legg til ```UserInfoRestService``` i pakken ```no.bouvet.sandvika.oauth2.rest```.

```java
package no.bouvet.sandvika.oauth2.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import no.bouvet.sandvika.oauth2.GithubUserInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

@Slf4j
@RestController
public class UserInfoRestService
{
    private final ObjectMapper objectMapper;

    public UserInfoRestService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @RolesAllowed({"ROLE_USER"})
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    @ResponseBody
    public Object userInfo(Authentication authentication)
    {
        return objectMapper.convertValue(((OAuth2Authentication)authentication).getUserAuthentication().getDetails(), GithubUserInfo.class);
    }
}
```

Gå til ```http://localhost:9292/``` og logg inn med dine GitHub credentials. Du burde få opp en enkel html på root som viser din brukerinfo.

### Oppgave 1 - Konfigurer OAuth 2.0 server
Vi skal konfigurere en OAuth 2.0 provider ved hjelp av Spring Boot og Spring Security. Applikasjonen skal utstede tokens med støtte for [JSON Web Tokens (JWT)](https://jwt.io/). Med JWT kodes brukerinformasjonen med autorisasjoner inn i tokenet, fremfor å kalle et eget user-info endepunkt.

#### 1.0 Enable authorization server
For å kjøre opp en minimal Spring boot authorization server må ```@EnableAuthorizationServer``` legges til i spring konfigurasjonen samt minst én klient må konfigureres i ```application.yaml```.

Fullfør konfigurasjonen i prosjektet ```oauth2-authorization-server``` slik at applikasjonen tilfredstiller et absolutt minimum. Benytt clientId: ```oauth2-client``` og secret: ```client-password```. 

Start opp auth serveren slik at den kjører på port 9191. 

#### 1.1 Test med curl
```curl
curl oauth2-client:client-password@localhost:9191/as/oauth/token -dgrant_type=client_credentials -dscope=any
```

Skal gi response:
```json
{
  "access_token": "9f21ae47-2fbb-4f79-b3c7-eedd9d90c060",
  "token_type": "bearer",
  "expires_in": 43199,
  "scope": "any"
}
```

#### 1.2 Form login og authorization code grant
Form login enables via ```WebSecurityConfigurerAdapter``` og ```@EnableWebSecurity```. Opprett en ny spring konfig i pakken ```no.bouvet.sandvika.oauth2.authorization.config``` med navn ```FormLoginWebSecurityConfig```. 

```java
package no.bouvet.sandvika.oauth2.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class FormLoginWebSecurityConfig extends WebSecurityConfigurerAdapter {

    //@formatter:off
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http.csrf().disable()
            .authorizeRequests()
            .anyRequest()
                .authenticated()
            .and()
            .formLogin()
                .permitAll();
    }
    //@formatter:on

    //@formatter:off
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("oauth2-user")
                .password("user-password")
                .roles("USER");
    }
    //@formatter:on

    @Bean
    @SuppressWarnings("deprecation")
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
``` 

Opprett en ny spring config klasse med navn ```AuthorizationServerConfig``` i samme pakke som over, klassen skal være et sentralt sted for konfigurasjon av authorization server.

* ```AuthorizationServerConfig``` skal extende ```AuthorizationServerConfigurerAdapter```
* ```AuthorizationServerConfig``` skal være annotert med ```@Configuration```og ```@EnableAuthorizationServer```.
* ```AuthorizationServerConfig``` skal overskrive metoden ```public void configure(ClientDetailsServiceConfigurer clientDetailsServiceConfigurer) throws Exception```. Benytt ```InMemoryClientDetailsServiceBuilder``` til å konfigurere oauth2 klienten fra steg 1.0.

| Property | Verdi | 
| -------- | ----- |
| clientId | oauth2-client | 
| secret | client-password | 
| authorizedGrantTypes | authorization_code | 
| accessTokenUri | https://github.com/login/oauth/access_token | 
| scope | read | 
| redirectUris | http://localhost:9292/login | 
| autoApprove | true |

#### 1.3 Test med curl
på tide å teste applikasjonen.
Request client authentication på /oauth/authorize. Bruker er ikke logget inn og serveren returnerer 302 til /login
```curl
curl -i -c cookies.txt "http://localhost:9191/as/oauth/authorize" -d "response_type=code&client_id=oauth2-client"
```
Bruker må logge inn med form login. Hvis autentiseringen er vellykket så returnerer serveren 302 til /oauth/authorize
```curl
curl -i -b cookies.txt -c cookies.txt "http://localhost:9191/as/login" -d "username=oauth2-user&password=user-password"
```
Bruker kaller /oauth/authorize igjen (med cookie jsessionid). Server responderer med en access code 
```curl
code=$(curl -si -b cookies.txt "http://localhost:9191/as/oauth/authorize" -d "redirect_uri=http://localhost:9292/login" | ggrep -oP 'Location:.*code=\K\w+')
```
Klienten kaller /oauth/token med access code og får returnert access token.  
```curl
curl -i -u "oauth2-client:client-password" "http://localhost:9191/as/oauth/token" -d "code=$code&grant_type=authorization_code&redirect_uri=http://localhost:9292/login"
```

Dette skal gi følgende respons:
```
HTTP/1.1 200 
Pragma: no-cache
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Tue, 12 Nov 2019 12:47:40 GMT

{"access_token":"1b03b4a4-4c6c-4e9d-9be9-a79530c525fc","token_type":"bearer","expires_in":43199,"scope":"read"}
```

#### 1.4 JSON Web Token (JWT)
JSON Web token er støttet av veldig mange rammeverk både i java og JavaScript (Passport) og er en måte å kode inn autorisasjoner i access tokenet, samt annen nyttig brukerinfo. 

Utvid klassen ```AuthorizationServerConfig``` ved å importere configuration ```AuthorizationServerTokenServicesConfiguration.class``` i ```@Import```.

Autowire/inject ```JwtAccessTokenConverter``` og overskriv metoden som vist under. 
````java
@Override
public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
    // Use AccessTokenConverter from AuthorizationServerTokenServicesConfiguration for JWT token support
    endpoints.accessTokenConverter(accessTokenConverter);
}
````

Utvid ```application.yaml``` med følgende konfigurasjon:
```yaml
security:
  oauth2:
    authorization:
      jwt:
        key-value: secret-jwt-key # Access token shared secret (valgfri secret)
```

I spring boot application klassen (```AuthorizationServerApplication```) legg til ```@EnableConfigurationProperties(AuthorizationServerProperties.class) // JWT token support```

Start opp serveren igjen og rekjør curl testen fra steg 1.3.

Trekk ut access tokenet og gå til www.jwt.io. Valider tokenet i validatoren. 

Resultatet burde være noe liknende:
```json
{
  "exp": 1573608355,
  "user_name": "oauth2-user",
  "authorities": [
    "ROLE_USER"
  ],
  "jti": "21b2bc41-65fc-4b25-a489-9f969a45340c",
  "client_id": "oauth2-client",
  "scope": [
    "read"
  ]
}
```

#### 1.5 Spring resource server
I OAuth 2.0 spesifikasjonen er en resource server en tjeneste som tilbyr beskyttede data. Det kan være authorization serveren selv som også holder på beskyttede data eller en annen backend service.

Utvid prosjektet ```oauth2-resource-server``` til å faktisk være en resource server med jsr250 og JWT støtte.

Hints:
* konfigurer jwt.key-value i application.yaml
* benytt @EnableResourceServer
* benytt @EnableGlobalMethodSecurity
* benytt @RolesAllowed i rest service

#### 1.5 Spring client
Konfigurer ```oauth2-spring-client``` fra oppgave 0 til å benytte den nye ```oauth2-authorization-server```. Husk at klienten må vite om jwt.key-value.

For at klienten skal kunne kalle resource server må ````restTemplate```` konfigureres, legg til følgende bean.
```java
@Bean
public RestTemplate restTemplate() {
    return new RestTemplateBuilder()
            .interceptors((request, body, execution) -> {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth.getDetails() instanceof OAuth2AuthenticationDetails) {
                    OAuth2AuthenticationDetails oAuth2AuthDetails = (OAuth2AuthenticationDetails) auth.getDetails();
                    request.getHeaders().add(HttpHeaders.AUTHORIZATION, "Bearer " + oAuth2AuthDetails.getTokenValue());
                }
                return execution.execute(request, body);

            }).errorHandler(new DefaultResponseErrorHandler() {
        @Override
        public boolean hasError(ClientHttpResponse response) throws IOException {
            if (response.getStatusCode() == HttpStatus.UNAUTHORIZED &&
                    response.getHeaders().containsKey(HttpHeaders.WWW_AUTHENTICATE)) {
                return false; // Do not throw Exception on token related errors
            }
            return super.hasError(response);
        }
    }).build();
}
``` 

Legg til en rest service som kan kalle resource server sitt endepunkt /hentBackendData som vist under

```java
package no.bouvet.sandvika.oauth2.rest;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class BackendRestService {
    private final RestTemplate restTemplate;

    public BackendRestService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @RequestMapping(value = "/data", produces = MediaType.APPLICATION_JSON_UTF8_VALUE, method = RequestMethod.GET)
    public String getData() {
        return restTemplate.getForEntity("http://localhost:9393/hentBackendData", String.class).getBody();
    }
}
```

Lag et DTO objekt som kan holde på brukerinfo som vist under.
```java
package no.bouvet.sandvika.oauth2.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ` ` {
    private String username;
    private String authorities;
    private String clientId;
    private String scope;
}
```

Endre ```UserInfoRestService``` fra oppgave 0 til å returnere ```UserInfoRestService```.
```java
package no.bouvet.sandvika.oauth2.rest;

import lombok.extern.slf4j.Slf4j;
import no.bouvet.sandvika.oauth2.dto.UserInfoDto;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

@Slf4j
@RestController
public class UserInfoRestService
{
    @RolesAllowed({"ROLE_USER"})
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    @ResponseBody
    public UserInfoDto userInfo(OAuth2Authentication authentication)
    {
        return UserInfoDto.builder()
                .username(authentication.getName())
                .authorities(authentication.getAuthorities().toString())
                .clientId(authentication.getOAuth2Request().getClientId())
                .scope(authentication.getOAuth2Request().getScope().toString())
                .build();
    }
}
```

#### 1.7 Test klient og resource server
Star applikasjonene ```oauth2-authorization-server``` og ```oauth2-spring-client```. Gå til siden ```http://localhost:9292```. Logg inn med oauth2-user og user-password. Du skal nå få opp en User Info html side.

Prøv å naviger til ```http://localhost:9393/hentBackendData```. Du skal få error -> unauthorized.

### Oppgave 2 - Legge til user og client properties støtte
Det kan være veldig nyttig å kunne lese inn user og client konfigurasjon via properties i ```application.yaml``` fromfor å hardkode klienten i koden.

I prosjektet ```oauth2-authorization-server``` opprett tre nye pojo klasser i pakken ```no.bouvet.sandvika.oauth2.authorization.properties```.
```java
package no.bouvet.sandvika.oauth2.authorization.properties;

import lombok.*;

import java.util.Set;

import static java.util.Collections.emptySet;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode
@ToString(exclude = "secret")
public class ClientProperties {

    private String clientId;
    private String secret;
    @Builder.Default
    private Set<String> grantTypes = emptySet();
    @Builder.Default
    private Set<String> scopes = emptySet();
    @Builder.Default
    private Set<String> redirectUris = emptySet();
}
```
```java
package no.bouvet.sandvika.oauth2.authorization.properties;

import lombok.*;

import java.util.Set;

import static java.util.Collections.emptySet;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode
@ToString(exclude = "password")
public class UserProperties {

    private String username;
    private String password;
    @Builder.Default
    private Set<String> authorities = emptySet();
}
```
```java
package no.bouvet.sandvika.oauth2.authorization.properties;

import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

import static java.util.Collections.emptyList;

@ConfigurationProperties("bouvet.authorization")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode
@ToString
public class AuthorizationProperties {

    @Builder.Default
    private List<UserProperties> users = emptyList();
    @Builder.Default
    private List<ClientProperties> clients = emptyList();
}
```

Legg til ``AuthorizationProperties`` i ```@EnableConfigurationProperties```.

Endre properties i ```application.yaml```
```yaml
bouvet:
  authorization:
    users:
      - username: oauth2-user
        password: user-password
        authorities:
          - ROLE_USER
      - username: oauth2-admin
        password: admin-password
        authorities:
          - ROLE_USER
          - ROLE_ADMIN
    clients:
      - client-id: oauth2-client
        secret: client-password
        grant-types:
          - authorization_code
        scopes:
          - read
        redirect-uris:
          - http://localhost:9292/login
```

Nå, i ```AuthorizationServerConfig``` gjør om ```ClientDetailsServiceConfigurer``` til å benytte properties fra ```application.yaml```. Koden burde bli noe liknende metoden under. 

```java
@Override
public void configure(ClientDetailsServiceConfigurer clientDetailsServiceConfigurer) throws Exception {
    InMemoryClientDetailsServiceBuilder clientDetailsServiceBuilder = clientDetailsServiceConfigurer.inMemory();

    clientPropertiesList.forEach(clientProperties -> clientDetailsServiceBuilder
        .withClient(clientProperties.getClientId())
            .secret(clientProperties.getSecret())
            .authorizedGrantTypes(clientProperties.getGrantTypes().toArray(new String[0]))
            .scopes(clientProperties.getScopes().toArray(new String[0]))
            .redirectUris(clientProperties.getRedirectUris().toArray(new String[0]))
            .accessTokenValiditySeconds(sessionTimeout)
            .autoApprove(true));
}
```

Start opp ```oauth2-authorization-server``` og test ut klienten fra oppgave 1.7.

### Oppgave 3 - Benytt asymmetriske nøkler for signering av access token
