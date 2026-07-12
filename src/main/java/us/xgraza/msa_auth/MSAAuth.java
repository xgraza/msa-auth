package us.xgraza.msa_auth;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @author xgraza 7/11/2026
 */
public final class MSAAuth
{
    /**
     * User agent used for requests
     */
    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0";

    /**
     * The HTTP client used for all the requests.
     * Options are used to allow redirects and to save cookies.
     * Both are required to prevent issues grabbing the SFTT tag or the urlPost value
     */
    private static final CloseableHttpClient HTTP_CLIENT = HttpClientBuilder
            .create()
            .setRedirectStrategy(new LaxRedirectStrategy())
            .setUserAgent(USER_AGENT)
            .disableAuthCaching()
            .disableCookieManagement()
            .build();

    // All the API URLs we will need... holy
    private static final String OAUTH_AUTH_DESKTOP_URL = "https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en";
    private static final String OAUTH_AUTHORIZE_URL = "https://login.live.com/oauth20_authorize.srf?response_type=code&client_id=%s&redirect_uri=http://localhost:%s/login&code_challenge=%s&code_challenge_method=S256&scope=XboxLive.signin+offline_access&state=NOT_NEEDED&prompt=select_account";
    private static final String OAUTH_TOKEN_URL = "https://login.live.com/oauth20_token.srf";
    private static final String XBOX_LIVE_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
    private static final String XBOX_XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
    private static final String LOGIN_WITH_XBOX_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
    private static final String MINECRAFT_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

    // Patterns to grab important information from the returned HTML
    private static final Pattern SFTT_TAG_PATTERN = Pattern.compile("value=\\\\\"(.+?)\\\\\"");
    private static final Pattern POST_URL_PATTERN = Pattern.compile("\"urlPost\":\"(.+?)\"");

    /**
     * The port used for the localhost redirect
     */
    private static int CALLBACK_PORT = 8080;

    /**
     * The client ID from the Azure project
     */
    private static String CLIENT_ID;

    // Server stuff
    private static HttpServer CALLBACK_SERVER;
    private static boolean SERVER_OPEN;
    private static PKCEData PKCE_DATA;

    private MSAAuth()
    {
        // everything is static
        throw new RuntimeException("Do not create a new instance of MicrosoftAuthenticator. Static methods only");
    }

    /**
     * Gets a {@link MinecraftProfile} via an email & password login
     * @param email the account email
     * @param password the account password
     * @return the {@link MinecraftProfile} or null if failure
     * @apiNote This may error if the account is a Child/Teen account or has 2FA enabled
     */
    public static MinecraftProfile getProfile(final String email, final String password)
    {
        final OAuthResult result = getOAuth();
        final String token = getOAuthLoginData(result, email, password);
        final XBLData data = authWithXboxLive(token, false);
        requestTokenFromXboxLive(data);
        final String accessToken = loginWithXboxLive(data);
        PKCE_DATA = null;
        return fetchMinecraftProfile(accessToken);
    }

    /**
     * Gets a {@link MinecraftProfile} with an access token
     * @param token the access token
     * @param browser if the access token was obtained via a browser (usually false)
     * @return the {@link MinecraftProfile} or null if a failure
     */
    public static MinecraftProfile getProfile(final String token, final boolean browser)
    {
        final XBLData data = authWithXboxLive(token, browser);
        requestTokenFromXboxLive(data);
        final String accessToken = loginWithXboxLive(data);
        PKCE_DATA = null;
        return fetchMinecraftProfile(accessToken);
    }

    /**
     * Gets a {@link MinecraftProfile} from an OAuth2 code
     * @param code the OAuth2 code
     * @param browser if the code was obtained via the browser login
     * @return the {@link MinecraftProfile} or null if a failure
     */
    public static MinecraftProfile getProfileFromOAuth2(final String code, final boolean browser)
    {
        return getProfile(getLoginToken(code), browser);
    }

    /**
     * Creates a localhost server to start an OAuth2 login
     * @param callback the callback with the OAuth2 code
     * @return the URL the user will need to click to login to their MS account and authorize it with your Azure application
     * @throws IOException
     * @throws MSAAuthException
     */
    public static String loginWithBrowser(final Consumer<String> callback)
            throws IOException, MSAAuthException
    {
        if (!SERVER_OPEN || CALLBACK_SERVER == null)
        {
            CALLBACK_SERVER = HttpServer.create();
            CALLBACK_SERVER.createContext("/login", (ctx) ->
            {
                final Map<String, String> query = parseQueryString(ctx.getRequestURI().getQuery());

                if (query.containsKey("error"))
                {
                    final String errorDescription = query.get("error_description");
                    if (errorDescription != null && !errorDescription.isEmpty())
                    {
                        writeToWebpage("Failed to get token: " + errorDescription, ctx);
                    }
                } else
                {
                    final String code = query.get("code");
                    if (code != null)
                    {
                        writeToWebpage("Successfully got code. You may now close this window", ctx);
                        callback.accept(code);
                    } else
                    {
                        writeToWebpage("Failed to get code. Please try again.", ctx);
                        callback.accept(null);
                    }
                }
                SERVER_OPEN = false;
                CALLBACK_SERVER.stop(0);
            });
        }

        PKCE_DATA = generateKeys();
        if (PKCE_DATA == null)
        {
            throw new MSAAuthException("Failed to generate PKCE keys for MS OAuth2");
        }

        if (!SERVER_OPEN)
        {
            CALLBACK_SERVER.bind(new InetSocketAddress(CALLBACK_PORT), 1);
            CALLBACK_SERVER.start();
            SERVER_OPEN = true;
        }

        return String.format(OAUTH_AUTHORIZE_URL, CLIENT_ID, CALLBACK_PORT, PKCE_DATA.challenge);
    }

    /**
     * Gets the OAuth2 access token for a desktop login
     * @param oauthToken the oauth login
     * @return the access token
     * @throws MSAAuthException if we could not obtain the access token from the OAuth2 token
     */
    private static String getLoginToken(final String oauthToken) throws MSAAuthException
    {
        final HttpPost request = new HttpPost(OAUTH_TOKEN_URL);
        {
            request.setHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
            request.setHeader("Accept", "application/json");
            request.setHeader("Origin", String.format("http://localhost:%s/", CALLBACK_PORT));
            request.setEntity(new StringEntity(
                    makeQueryString(new String[][]{
                            new String[]{ "client_id", CLIENT_ID },
                            new String[]{ "code_verifier", PKCE_DATA.verifier },
                            new String[]{ "code", oauthToken },
                            new String[]{ "grant_type", "authorization_code" },
                            new String[]{ "redirect_uri", String.format("http://localhost:%s/login", CALLBACK_PORT) }
                    }),
                    ContentType.create(ContentType.APPLICATION_FORM_URLENCODED.getMimeType(), Charset.defaultCharset())));
        }

        try (final CloseableHttpResponse response = HTTP_CLIENT.execute(request))
        {
            final String content = EntityUtils.toString(response.getEntity());
            if (content == null || content.isEmpty())
            {
                throw new MSAAuthException("Failed to get login token from MSA OAuth");
            }
            final JsonObject obj = new JsonParser().parse(content).getAsJsonObject();
            if (obj.has("error"))
            {
                throw new MSAAuthException(obj.get("error").getAsString() + ": " + obj.get("error_description").getAsString());
            }
            return obj.get("access_token").getAsString();
        } catch (final IOException e)
        {
            throw new MSAAuthException("Failed to get login token");
        }
    }

    /**
     * Gets desktop OAuth2 data to login
     * @return a {@link OAuthResult} containing the Cookie, SFTT tag, and the redirect post URL
     * @throws MSAAuthException if we could not get the SFTT tag or redirect post URL
     */
    private static OAuthResult getOAuth() throws MSAAuthException
    {
        final HttpGet request = new HttpGet(OAUTH_AUTH_DESKTOP_URL);
        request.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");

        try (final CloseableHttpResponse response = HTTP_CLIENT.execute(request))
        {
            final String content = EntityUtils.toString(response.getEntity());

            Matcher matcher = SFTT_TAG_PATTERN.matcher(content);
            if (!matcher.find())
            {
                throw new MSAAuthException("Failed to get SFTT tag from MS desktop OAuth");
            }
            final String sfttTag = matcher.group(1);
            if (!(matcher = POST_URL_PATTERN.matcher(content)).find())
            {
                throw new MSAAuthException("Failed to get the new post redirect URL from MS desktop OAuth");
            }
            final String postUrl = matcher.group(1);
            return new OAuthResult(sfttTag, postUrl,
                    Arrays.stream(response.getHeaders("Set-Cookie"))
                    .map(Header::getValue)
                    .collect(Collectors.joining(";")));
        } catch (final IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Gets an access token from OAuth2 data w/ email & password
     * @param result the previous {@link OAuthResult}
     * @param email the account email
     * @param password the account password
     * @return the access token
     * @throws MSAAuthException if the access token was not able to be got
     */
    @SuppressWarnings("deprecation")
    private static String getOAuthLoginData(final OAuthResult result, final String email, final String password) throws MSAAuthException
    {
        final HttpPost request = new HttpPost(result.postUrl);
        {
            request.setHeader("Cookie", result.cookie);
            request.setHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.getMimeType());

            // Encode our email & password and add to our request as a query
            final String encodedEmail = URLEncoder.encode(email);
            final String encodedPassword = URLEncoder.encode(password);
            request.setEntity(new StringEntity(
                    makeQueryString(new String[][]{
                            new String[]{ "login", encodedEmail },
                            new String[]{ "loginfmt", encodedEmail },
                            new String[]{ "passwd", encodedPassword },
                            new String[]{ "PPFT", result.sfttTag }
                    }), ContentType.create(ContentType.APPLICATION_FORM_URLENCODED.getMimeType())));
        }

        final HttpClientContext ctx = HttpClientContext.create();
        try (final CloseableHttpResponse response = HTTP_CLIENT.execute(request, ctx))
        {
            final List<URI> redirectLocations = ctx.getRedirectLocations();
            if (redirectLocations != null && !redirectLocations.isEmpty())
            {
                final String query = redirectLocations.get(redirectLocations.size() - 1).toString().split("#")[1];
                for (final String param : query.split("&"))
                {
                    final String[] parameter = param.split("=");
                    if (parameter[0].equals("access_token"))
                    {
                        return parameter[1];
                    }
                }
            } else
            {
                throw new MSAAuthException("Failed to get valid response from Microsoft");
            }

            final String content = EntityUtils.toString(response.getEntity());
            if (content != null && !content.isEmpty())
            {
                if (content.contains("Sign in to"))
                {
                    throw new MSAAuthException("The provided credentials were incorrect");
                } else if (content.contains("Help us protect your account"))
                {
                    throw new MSAAuthException("2FA has been enabled on this account");
                }
            }
        } catch (IOException e)
        {
           throw new MSAAuthException("Failed to get access token");
        }

        throw new MSAAuthException("Failed to get access token");
    }

    /**
     * Logs into the Xbox Live account via the access token from the Microsoft account
     * @param accessToken the Microsoft account access token
     * @param browser if the access token was obtained by a browser login (local)
     * @return the {@link XBLData} containing the token & user hash
     * @throws MSAAuthException if we were unable to get the Xbox Live account data
     */
    private static XBLData authWithXboxLive(final String accessToken, final boolean browser) throws MSAAuthException
    {
        final JsonObject bodyObject = new JsonObject();
        {
            bodyObject.addProperty("TokenType", "JWT");
            bodyObject.addProperty("RelyingParty", "http://auth.xboxlive.com");
            final JsonObject propertiesObject = new JsonObject();
            {
                propertiesObject.addProperty("AuthMethod", "RPS");
                propertiesObject.addProperty("SiteName", "user.auth.xboxlive.com");
                propertiesObject.addProperty("RpsTicket", (browser ? "d=" : "t=") + accessToken);
            }
            bodyObject.add("Properties", propertiesObject);
        }
        final String content = post(XBOX_LIVE_AUTH_URL, bodyObject.toString());
        if (content != null && !content.isEmpty())
        {
            final JsonObject object = new JsonParser().parse(content).getAsJsonObject();
            final XBLData data = new XBLData();
            data.setToken(object.get("Token").getAsString());
            data.setUserHash(object.get("DisplayClaims").getAsJsonObject()
                    .get("xui").getAsJsonArray()
                    .get(0).getAsJsonObject()
                    .get("uhs").getAsString());
            return data;
        }
        throw new MSAAuthException("Failed to authenticate with Xbox Live account");
    }

    /**
     * Exchanges the Xbox live token for an XSTS token
     * @param data the {@link XBLData} obtained from {@link MSAAuth#authWithXboxLive(String, boolean)}
     * @throws MSAAuthException if we could not get the Xbox Live XSTS token
     */
    private static void requestTokenFromXboxLive(final XBLData data) throws MSAAuthException
    {
        final JsonObject bodyObject = new JsonObject();
        {
            bodyObject.addProperty("RelyingParty", "rp://api.minecraftservices.com/");
            bodyObject.addProperty("TokenType", "JWT");
            final JsonObject propertiesObject = new JsonObject();
            {
                propertiesObject.addProperty("SandboxId", "RETAIL");
                final JsonArray userTokensArray = new JsonArray();
                {
                    userTokensArray.add(data.getToken());
                }
                propertiesObject.add("UserTokens", userTokensArray);
            }
            bodyObject.add("Properties", propertiesObject);
        }
        final String content = post(XBOX_XSTS_AUTH_URL, bodyObject.toString());
        if (content != null && !content.isEmpty())
        {
            final JsonObject object = new JsonParser().parse(content).getAsJsonObject();
            if (object.has("XErr"))
            {
                throw new MSAAuthException("Xbox Live Error: " + object.get("XErr").getAsString());
            } else
            {
                data.setToken(object.get("Token").getAsString());
                return;
            }
        }
        throw new MSAAuthException("Failed to get XSTS token");
    }

    /**
     * Logs in with an Xbox Live identity token (NOT account Token)
     * @param data the {@link XBLData} with the modified object from {@link MSAAuth#requestTokenFromXboxLive(XBLData)}
     * @return the access token for the Xbox Live account
     * @throws MSAAuthException if we could not get the Xbox Live access token
     */
    private static String loginWithXboxLive(final XBLData data) throws MSAAuthException
    {
        final JsonObject bodyObject = new JsonObject();
        {
            bodyObject.addProperty("ensureLegacyEnabled", "true");
            bodyObject.addProperty("identityToken", String.format("XBL3.0 x=%s;%s", data.getUserHash(), data.getToken()));
        }
        final String content = post(LOGIN_WITH_XBOX_URL, bodyObject.toString());
        if (content != null && !content.isEmpty())
        {
            final JsonObject object = new JsonParser().parse(content).getAsJsonObject();
            if (object.has("errorMessage"))
            {
                throw new MSAAuthException(object.get("errorMessage").getAsString());
            }
            if (object.has("access_token"))
            {
                return object.get("access_token").getAsString();
            }
        }
        return null;
    }

    /**
     * Gets a Minecraft profile from Mojang via an Xbox Live access token
     * @param accessToken the Xbox Live account access token
     * @return a {@link MinecraftProfile} object or null if the response did not have a 200 response code
     * @throws MSAAuthException if the profile was unable to be fetched due to an API error
     */
    private static MinecraftProfile fetchMinecraftProfile(final String accessToken) throws MSAAuthException
    {
        final HttpGet request = new HttpGet(MINECRAFT_PROFILE_URL);
        {
            request.setHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());
            request.setHeader("Authorization", "Bearer " + accessToken);
        }

        try (final CloseableHttpResponse response = HTTP_CLIENT.execute(request))
        {
            final int code = response.getStatusLine().getStatusCode();
            if (code != 200)
            {
                throw new MSAAuthException("Failed to fetch MC profile: Status code != 200, sc=" + code);
            }
            final String rawJSON = EntityUtils.toString(response.getEntity());
            final JsonObject object = new JsonParser().parse(rawJSON).getAsJsonObject();
            if (object.has("error"))
            {
                throw new MSAAuthException("Failed to fetch MC profile: " + object.get("error").getAsString() + " -> " + object.get("errorMessage").getAsString());
            }
            return new MinecraftProfile(object.get("name").getAsString(),
                    object.get("id").getAsString());
        } catch (IOException e)
        {
            throw new MSAAuthException(e.getMessage());
        }
    }

    /**
     * Makes a POST request
     * @param url the URL
     * @param body the body
     * @return the content from the request
     */
    private static String post(final String url, final String body)
    {
        final HttpPost request = new HttpPost(url);
        {
            request.setHeader("Content-Type", ContentType.APPLICATION_JSON.getMimeType());
            request.setHeader("Accept", "application/json");
            request.setEntity(new StringEntity(
                    body, ContentType.create(
                    ContentType.APPLICATION_JSON.getMimeType(),
                    Charset.defaultCharset())));
        }
        try (final CloseableHttpResponse response = HTTP_CLIENT.execute(request))
        {
            return EntityUtils.toString(response.getEntity());
        } catch (final IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Helper function to write to the redirect localhost server for OAuth2 browser login (local)
     * @param message the message to display
     * @param ext the HTTP context
     * @throws IOException if the OutputStream could not be wrote to/closed
     */
    private static void writeToWebpage(final String message, final HttpExchange ext) throws IOException
    {
        final byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        ext.sendResponseHeaders(200, message.length());
        // Write to the output stream (this will allow the user to see the message)
        final OutputStream outputStream = ext.getResponseBody();
        outputStream.write(bytes, 0, bytes.length);
        outputStream.close();
    }

    /**
     * Creates a query string from a 2D array
     * @param parameters an array of String[] (lenght 2, key,value pairs)
     * @return the query string for a URL request
     */
    private static String makeQueryString(final String[][] parameters)
    {
        final StringJoiner joiner = new StringJoiner("&");
        for (final String[] parameter : parameters)
        {
            joiner.add(parameter[0] + "=" + parameter[1]);
        }
        return joiner.toString();
    }

    /**
     * Parses a query string (key,value) into a Map
     * @param query the plaintext query string
     * @return a {@link Map} of the query string key & value
     */
    private static Map<String, String> parseQueryString(final String query)
    {
        final Map<String, String> parameterMap = new LinkedHashMap<>();
        for (final String part : query.split("&"))
        {
            final String[] kv = part.split("=");
            parameterMap.put(kv[0], kv.length == 1 ? null : kv[1]);
        }
        return parameterMap;
    }

    /**
     * Generates PKCE code & verifier for the OAuth2 login (local)
     * @return the {@link PKCEData} data or null if failure
     */
    private static PKCEData generateKeys()
    {
        try
        {
            final byte[] randomBytes = new byte[32];
            new SecureRandom().nextBytes(randomBytes);

            final String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
            final byte[] verifierBytes = verifier.getBytes(StandardCharsets.US_ASCII);
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(verifierBytes, 0, verifierBytes.length);

            final byte[] d = digest.digest();
            final String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(d);
            return new PKCEData(challenge, verifier);
        } catch (Exception ignored)
        {
        }
        return null;
    }

    /**
     * Sets the callback port for the localhost redirect to grab the authentication token
     * @param port the localhost port to use
     */
    public static void setCallbackPort(final int port)
    {
        CALLBACK_PORT = port;
    }

    /**
     * Sets the client ID for the azure application for OAuth2 logins
     * @param clientID the azure application client id
     */
    public static void setClientID(final String clientID)
    {
        CLIENT_ID = clientID;
    }
}
