package no.bouvet.sandvika.oauth2.resource.server.rest;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

import static java.lang.String.format;

@RestController
public class ResourceRestService {

    @ResponseBody
    @RequestMapping(value = "/hentBackendData")
    public String hentData(OAuth2Authentication auth) {
        if (auth.getUserAuthentication() != null) {
            return format("Hello user '%s'. You have the following authorities: %s. Your client '%s' has the following scopes: %s",
                    auth.getPrincipal(),
                    auth.getAuthorities(),
                    auth.getOAuth2Request().getClientId(),
                    auth.getOAuth2Request().getScope());
        } else {
            return "Unknown authentication!";
        }
    }
}
