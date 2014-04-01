package me.loki2302;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import static me.loki2302.App.*;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = AppConfiguration.class)
@IntegrationTest
@WebAppConfiguration
public class AppTest {
    private RestTemplate restTemplate;

    @Before
    public void setUpRestTemplate() {
        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        restTemplate = new RestTemplate(requestFactory);
    }

    @After
    public void unsetRestTemplate() {
        restTemplate = null;
    }

    @Test
    public void notAuthenticatedByDefault() {
        try {
            restTemplate.getForObject("http://localhost:8080/api/me", Me.class);
            fail("Managed to retrieve user details without authentication");
        } catch(HttpClientErrorException e) {
            assertEquals(HttpStatus.FORBIDDEN, e.getStatusCode());
        }
    }

    @Test
    public void cantAuthenticateWithInvalidCredentials() {
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.username = "hacker";
        authenticationRequest.password = "123";

        try {
            restTemplate.postForObject(
                    "http://localhost:8080/api/authenticate",
                    authenticationRequest,
                    Me.class);

            fail("Managed to authenticate with invalid credentials");
        } catch(HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }

        try {
            restTemplate.getForObject("http://localhost:8080/api/me", Me.class);
            fail("Managed to retrieve user details without authentication");
        } catch(HttpClientErrorException e) {
            assertEquals(HttpStatus.FORBIDDEN, e.getStatusCode());
        }
    }

    @Test
    public void canAuthenticateWithValidCredentials() {
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.username = "user";
        authenticationRequest.password = "password";

        Me me = restTemplate.postForObject(
                "http://localhost:8080/api/authenticate",
                authenticationRequest,
                Me.class);

        assertNotNull(me);
        assertEquals("user", me.username);

        me = restTemplate.getForObject("http://localhost:8080/api/me", Me.class);
        assertNotNull(me);
        assertEquals("user", me.username);
    }

    // TODO: test for /api/deauthenticate
}
