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
| accessTokenUri | http://localhost:9191/as/oauth/token |
| userAuthorizationUri | http://localhost:9191/as/oauth/authorize |
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
public class UserInfoDto {
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

Oppdater display_token_info.js
```
function createRow(headerData, data) {
    var trElem = document.createElement('tr');
    trElem.classList.add('row', 'data');

    trElem.appendChild(createCell(headerData, 'th'));
    trElem.appendChild(createCell(data, 'td'));

    return trElem;
}

function createCell(innerHtml, cellType) {
    var tdElem = document.createElement(cellType);
    // tdElem.classList.add('cell', clazz);
    tdElem.innerHTML = innerHtml;
    return tdElem;
}

function renderUserInfo(userInfo) {
    var existingTableElem = document.getElementById('userInfoTable');
    var newTableElem = document.createElement('table');
    newTableElem.id = 'userInfoTable';
    newTableElem.classList.add('userInfoTable');

    newTableElem.appendChild(createRow('Username', userInfo.username));
    newTableElem.appendChild(createRow('Authorities', userInfo.authorities));
    newTableElem.appendChild(createRow('Client Id', userInfo.clientId));
    newTableElem.appendChild(createRow('Scope', userInfo.scope));

    if (existingTableElem) {
        existingTableElem.parentNode.removeChild(existingTableElem);
    }
    document.body.appendChild(newTableElem);
}

function retrieveAndRender() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/user');
    xhr.onload = function () {
        if (xhr.status === 200) {
            try {
                var tokenInfoListe = JSON.parse(xhr.response);
                renderUserInfo(tokenInfoListe);
            } catch (e) {
                console.log("Feil ved parsing/rendering av resultat fra tjenestekall");
            }
        } else {
            console.log("Forventet HTTP 200, fikk " + xhr.status);
        }
    };
    xhr.onerror = function () {
        console.log("Ukjent feil ved kall til tjeneste");
    };
    xhr.send();

    var xhrData = new XMLHttpRequest();
    xhrData.open('GET', '/data');
    xhrData.onload = function () {
        if (xhrData.status === 200) {
            try {
                document.getElementById('userInfoTable').appendChild(createRow('Backend data', xhrData.response))
            } catch (e) {
                console.log("Feil ved parsing/rendering av resultat fra tjenestekall");
            }
        } else {
            console.log("Forventet HTTP 200, fikk " + xhrData.status);
        }
    };
    xhrData.onerror = function () {
        console.log("Ukjent feil ved kall til tjeneste");
    };
    xhrData.send();
}

retrieveAndRender(); // Hent initielle data

```

#### 1.7 Test klient og resource server
Star applikasjonene ```oauth2-authorization-server``` og ```oauth2-spring-client```. 

Gå til siden ```http://localhost:9292```. Logg inn med oauth2-user og user-password. Du skal nå få opp en User Info html side.

Gå til siden ```http://localhost:9292/data``` for å hente data fra ressursserver via klient, ressursserver svarer med en enkel infoside.

Prøv å aksessere ```http://localhost:9393/hentBackendData``` direkte. Du skal få error -> unauthorized, da det kun er klient som kjenner tokenet.

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

### Oppgave 3 - Benytt asymmetriske signering av access token

Det er ofte ikke ønskelig at klienter og ressursservere skal kjenne til signeringsnøkkelen, da de dermed står fritt til å manipulere og utstede nye token.

Vi skal derfor konfigurere asymmetrisk kryptering. Dette fungerer på samme måten som TLS/SSL, nemlig at autoriseringsserveren signerer tokens vha. sin private key, 
mens tredjeparter kun kjenner til public key.

**Nøkler for autoriseringsserver er allerede generert og ligger klare i jks-mappen.**

#### 3.1 Konfigurer asymmetriske signering på autoriseringsserver

```authorization-server.jks``` inneholder nøkkelpar (private+public) for at autoriseringsserveren skal kunne signere tokens.
Kopier inn denne filen til resources-mappa i autoriseringsserver.

Rediger ```application.yaml``` og konfigurer key-store, key-store-password og key-alias (hint: prefix jks-filnavn med *classpath:*).

#### 3.2 Konfigurer asymmetriske signering på klient og ressursserver

```authorization-server-public.pubkey``` inneholder autoriseringsserverens public key. Erstatt secret i ```application.yaml``` med innholdet i denne.

Start alle tre applikasjonene på nytt og test at det fortsatt virker å logge på og vise data fra både ```http://localhost:9292``` og ```http://localhost:9292/data```

### Oppgave 4 - Filtrer authorities basert på klient

Det er ikke nødvendigvis ønskelig at det alltid skal genereres token som inneholder alle rettigheter en bruker har, ei heller at alle klienter skal være kjent med alle rollene en bruker har.

Vi skal derfor implementere filtrering av roller per klient, slik at det kun utstedes tokens med authorities som er relevante for klienten.

#### 4.1 Legg til konfigurasjonsstøtte for filtrering av roller i autorisasjonsserver

Legg til feltet ```Set<String> allowedAuthorities``` i ```ClientProperties```.

Legg til konfigurasjonsnøkkel allowed-authorities på oauth2-client i ```application.yaml```, legg til ROLE_USER som verdi.

#### 4.2 Implementer filtrering av roller i egen Bean i autorisasjonsserver

Opprett ny klasse ```token/FilterAuthoritiesAccessTokenConverter.java```

```java
package no.bouvet.sandvika.oauth2.authorization.token;

import lombok.extern.slf4j.Slf4j;
import no.bouvet.sandvika.oauth2.authorization.properties.AuthorizationProperties;
import no.bouvet.sandvika.oauth2.authorization.properties.ClientProperties;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@Slf4j
public class FilterAuthoritiesAccessTokenConverter extends DefaultAccessTokenConverter {

    private Map<String, Set<String>> clientAllowedAuthoritiesMap;

    public FilterAuthoritiesAccessTokenConverter(AuthorizationProperties authorizationProperties) {
        clientAllowedAuthoritiesMap = authorizationProperties.getClients().stream()
            .collect(Collectors.toMap(ClientProperties::getClientId, ClientProperties::getAllowedAuthorities));
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {

        Map<String, Object> accessTokenMap = new HashMap<>(super.convertAccessToken(token, authentication));

        if (accessTokenMap.get(AUTHORITIES) != null) {
            String clientId = authentication.getOAuth2Request().getClientId();
            Set<String> clientAllowedAuthorities = clientAllowedAuthoritiesMap.get(clientId);

            Set<Object> userAuthoritiesSet = (Set) accessTokenMap.get(AUTHORITIES);
            Set<String> filteredAuthorities = userAuthoritiesSet.stream()
                .map(String::valueOf)
                .filter(clientAllowedAuthorities::contains)
                .collect(Collectors.toSet());

            log.debug("User '{}' on client '{}' approved for authorities {}", authentication.getName(), clientId, filteredAuthorities);
            accessTokenMap.put(AUTHORITIES, filteredAuthorities);
        }
        return accessTokenMap;
    }
}
```

#### 4.3 Sett opp bruk av vår egen AccessTokenConverter på autorisasjonsserver

Rediger ```AuthorizationServerConfig```, legg til FilterAuthoritiesAccessTokenConverter i konstruktør og ta vare på verdien i et felt i klassen.

I ```configure(AuthorizationServerEndpointsConfigurer endpoints)```, legg til linjen:
```java
accessTokenConverter.setAccessTokenConverter(filterAuthoritiesAccessTokenConverter);
```

Start authorization-server på nytt, gå inn på ```http://localhost:9292```, logg på som oauth2-admin og verifiser at listen over authorizations kun inneholder ROLE_USER.

### Oppgave 5 - Oppsett av client-auth med x509, og TLS/SSL kryptering mellom autorisasjonsserver og klient

Ved å aktivere TLS/SSL på autorisasjonsserver og bruke client-auth, så kan vi kutte ut client-secret. 

#### 5.1 Sett opp TLS/SSL på autorisasjonsserver

Kopier inn ```jks/client/oauth2-client-public.jks``` som ```resources/authorization-server-trust.jks```.

Rediger ```application.yaml```, aktiver ssl ved å legge til disse linjene under server:
```yaml
server:
  port: 9191
  ssl:
    key-store: classpath:authorization-server.jks
    key-store-password: Super Secret JWT Keypass
    key-alias: authorization-server
    trust-store: classpath:authorization-server-trust.jks
    trust-store-password: Super Secret JWT Keypass
```

#### 5.2 Konfigurer støtte for client-auth på egen port (benyttes for token-endepunkt)

Opprett ny klasse ```config/TomcatSslClientAuthConnectorConfiguration.java```

```java
package no.bouvet.sandvika.oauth2.authorization.config;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11JsseProtocol;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import static org.apache.tomcat.util.net.SSLHostConfig.CertificateVerification.REQUIRED;

@Configuration
@ConditionalOnProperty(name = "bouvet.authorization.client-auth-type", havingValue = "x509")
public class TomcatSslClientAuthConnectorConfiguration {

    @Bean
    public ServletWebServerFactory servletContainer(@Value("${bouvet.authorization.client-auth-port}") int port,
                                                    @Value("${server.ssl.key-store:}") String keyStore,
                                                    @Value("${server.ssl.key-store-password:}") String keyStorePassword,
                                                    @Value("${server.ssl.key-alias:}") String keyAlias,
                                                    @Value("${server.ssl.trust-store:}") String trustStore,
                                                    @Value("${server.ssl.trust-store-password:}") String trustStorePassword) {

        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setPort(port);
        connector.setScheme("https");
        connector.setSecure(true);

        AbstractHttp11JsseProtocol<?> protocolHandler = (AbstractHttp11JsseProtocol<?>) connector.getProtocolHandler();
        protocolHandler.setSSLEnabled(true);
        protocolHandler.setSslProtocol("TLS");
        protocolHandler.setClientAuth(REQUIRED.name());
        protocolHandler.setKeystoreFile(keyStore);
        protocolHandler.setKeystorePass(keyStorePassword);
        protocolHandler.setKeyAlias(keyAlias);
        protocolHandler.setTruststoreFile(trustStore);
        protocolHandler.setTruststorePass(trustStorePassword);

        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        tomcat.addAdditionalTomcatConnectors(connector);
        return tomcat;
    }
}
```

Legg til feltene ```String clientAuthType``` og ```Integer clientAuthPort``` i ```AuthorizationProperties```.

Rediger ```application.yaml```, aktiver client-auth via x509 ved å legge til disse linjene:
```yaml
bouvet:
  authorization:
    client-auth-type: x509
    client-auth-port: 9192
```

#### 5.3 Aktiver client-auth / x509-autentisering for klienter på autoriseringsserver

Vi må sette opp vår egen AuthorizationServerSecurityConfiguration.
Fjern derfor @EnableAuthorizationServer fra ```AuthorizationServerConfig.java```, da den drar inn standard AuthorizationServerSecurityConfiguration.

Opprett ny klasse ```config/X509AuthorizationServerSecurityConfiguration.java``` som extender AuthorizationServerSecurityConfiguration og overrider configure(HttpSecurity ..).
Med denne klassen så legger vi inn x509-støtte i filterchain, ved å i praksis legge dette foran UsernamePasswordAuthenticationFilter. 

```java
package no.bouvet.sandvika.oauth2.authorization.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.configuration.ClientDetailsServiceConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerSecurityConfiguration;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;

// Annotations copied from parent:
@Configuration
@Order(0)
@Import({ClientDetailsServiceConfiguration.class, AuthorizationServerEndpointsConfiguration.class})
public class X509AuthorizationServerSecurityConfiguration extends AuthorizationServerSecurityConfiguration {

    private final String clientAuthType;
    private final ClientDetailsService clientDetailsService;

    public X509AuthorizationServerSecurityConfiguration(@Value("${bouvet.authorization.client-auth-type}") String clientAuthType,
                                                        ClientDetailsService clientDetailsService) {
        this.clientAuthType = clientAuthType;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        if ("x509".equalsIgnoreCase(clientAuthType)) {
            http.apply(new SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>() {
                @Override
                public void init(HttpSecurity http) throws Exception {
                    X509AuthenticationFilter x509AuthenticationFilter = new X509AuthenticationFilter();
                    x509AuthenticationFilter.setAuthenticationManager(authenticationManagerBean());

                    http.httpBasic().disable()
                        .x509().x509AuthenticationFilter(x509AuthenticationFilter)
                        .userDetailsService(new ClientDetailsUserDetailsService(clientDetailsService));
                }
            });
        }
    }
}
```

#### 5.4 Sett opp klient for client-auth / x509-autentisering

Klargjør nøkkelpar på klient ved å kopiere ```jks/client/oauth2-client.jks``` til ```resources/oauth2-client.jks```.
Klargjør trust på autorisasjonsserver ved å kopiere inn ```jks/authorization-server/authorization-server-public.jks``` til ```resources/oauth2-client-trust.jks```

Rediger ```application.yaml```, aktiver ssl ved å legge til disse linjene under server:
```yaml
server:
  port: 9191
  ssl:
    key-store: classpath:authorization-server.jks
    key-store-password: Super Secret JWT Keypass
    key-alias: authorization-server
    trust-store: classpath:authorization-server-trust.jks
    trust-store-password: Super Secret JWT Keypass
```

Sett opp nye url'er til autorisasjonsserver, og deaktiver innsending av client-secret:
```yaml
security:
  oauth2:
    client:
      clientId: oauth2-client
      client-authentication-scheme: none # Vi bruker x509 i stedet. Dette valget skrur av innsending av client-id og secret ved henting av token
      accessTokenUri: https://localhost:9192/as/oauth/token
      userAuthorizationUri: https://localhost:9191/as/oauth/authorize
```

Tving RestTemplate (og alt annet) til å benytte vår key-store og trust-store ved å legge til en metode i ```OAuth2SecurityConfig```:

```java
    @Autowired
    private void configureKeyStores(@Value("${server.ssl.key-store}") String keyStore,
                                    @Value("${server.ssl.key-store-password}") String keyStorePassword,
                                    @Value("${server.ssl.trust-store}") String trustStore,
                                    @Value("${server.ssl.trust-store-password}") String trustStorePassword) throws FileNotFoundException
    {
        System.setProperty("javax.net.ssl.keyStore", ResourceUtils.getFile(keyStore).getAbsolutePath());
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
        System.setProperty("javax.net.ssl.trustStore", ResourceUtils.getFile(trustStore).getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
    }
```

Oppdater authorization-server med ny redirect_uri til klient ved å bytte ut http://... med https://...

#### 5.5 FINALE!

Sjekk at alt fungerer ved start oauth2-authorization-server og oauth2-spring-client på nytt, og gå inn på ```https://localhost:9292```, sjekk at alle data vises som før.
