package us.xgraza.msa_auth;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Properties;

/**
 * @author xgraza 7/11/2026
 * @apiNote Works as of 7/11/2026
 */
public class BrowserLoginTest
{
    private static final Properties PROPERTIES = new Properties();

    static
    {
        final File configFile = new File(System.getProperty("user.dir"), ".env");
        if (!configFile.exists())
        {
            throw new RuntimeException("Create a .env file");
        }
        try (final InputStream stream = Files.newInputStream(configFile.toPath()))
        {
            PROPERTIES.load(stream);
        } catch (final IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException
    {
        // required
        MSAAuth.setCallbackPort(6969);
        MSAAuth.setClientID(PROPERTIES.getProperty("azure_client_id"));

        final String url = MSAAuth.loginWithBrowser((oauth2Code) ->
        {
            if (oauth2Code == null)
            {
                throw new RuntimeException("Failed to get code");
            }
            final MinecraftProfile profile = MSAAuth.getProfileFromOAuth2(oauth2Code, true);
            System.out.println("Logged in as " + profile.getUsername() + " (" + profile.getId() + ")");
        });
        System.out.println("Use this URL: " + url);
    }
}
