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
public class EmailPasswordLoginTest
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

    public static void main(String[] args)
    {
        final String email = PROPERTIES.getProperty("email");
        final String password = PROPERTIES.getProperty("password");

        final MinecraftProfile profile = MSAAuth.getProfile(email, password);

        System.out.println("Logged in as " + profile.getUsername() + " (" + profile.getId() + ")");
    }
}
