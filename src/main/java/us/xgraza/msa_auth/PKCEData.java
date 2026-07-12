package us.xgraza.msa_auth;

/**
 * @author xgraza 7/11/2026
 * @apiNote Used for {@link MSAAuth} when using a browser login
 */
final class PKCEData
{
    public final String challenge, verifier;

    public PKCEData(final String challenge, final String verifier)
    {
        this.challenge = challenge;
        this.verifier = verifier;
    }
}
