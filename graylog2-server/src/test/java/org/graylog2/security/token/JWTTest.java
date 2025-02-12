package org.graylog2.security.token;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.junit.Assert;
import org.junit.Test;

public class JWTTest {


    @Test
    public void parseJWTToken() throws Exception {

        final String jwtToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3cE1IdTFibXZnRVZadGNCVmQ4cXR0UUlFbDR5SHlUbW8yY0d0YTZTd3dnIn0.eyJleH\n" +
                "AiOjE3MzMxNjA3NjcsImlhdCI6MTczMzE2MDQ2NywiYXV0aF90aW1lIjoxNzMzMTYwNDY2LCJqdGkiOiI1OWRmOGMzMC1mNTRiLTRjZTctYTA4MS1kMTQ4MmFhZjBjODciLCJpc3MiOiJodHRwOi8va3ViZS0xLmRldi5sb2dzLm92aC5jb206MzA5ODAvcmVhbG1zL215cmVhbG0iLCJhdWQiOiJhY2NvdW5\n" +
                "0Iiwic3ViIjoiNzYwYzc0YzAtN2Y5YS00NjJmLTgyODUtOTIyMjY2MTY3OGFhIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZ3JheWxvZyIsInNlc3Npb25fc3RhdGUiOiIzMDBkYTdiMS01YmM1LTQ2NGYtYTQxOS02NzVjOGZmMjY5YzEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9r\n" +
                "dWJlLTEuZGV2LmxvZ3Mub3ZoLmNvbTozMDkwMCIsImh0dHBzOi8vZ3cyc2Rldi1kb2NrZXIub3ZoLm5ldDoyMjQ0MSIsImh0dHA6Ly9ndzJzZGV2LWRvY2tlci5vdmgubmV0OjIyNDQwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW15cmVhbG0iLCJvZmZsaW5lX2FjY2Vzc\n" +
                "yIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCIsInNpZCI6IjMwMGRhN2IxLTViYz\n" +
                "UtNDY0Zi1hNDE5LTY3NWM4ZmYyNjljMSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IkJhYmFjYXIgRGlhc3PDqSIsInByZWZlcnJlZF91c2VybmFtZSI6ImJkaWFzc2UiLCJnaXZlbl9uYW1lIjoiQmFiYWNhciIsImZhbWlseV9uYW1lIjoiRGlhc3PDqSIsImVtYWlsIjoiYmFiYWNhci5kaWF\n" +
                "zc2VAY29ycC5vdmguY29tIn0.R31cbsWI1zooSua7JGvzi1A1fFT4HZrVSKjWjhxdMySjzdthZtKnPWq2zD2T7s_IrRVtNj7A1b8HxThHIJlfA4vGOgtrPaT6_pdtYfGkEXj45GOrn5UO5i2j1dHhDqjCK_wHLku7oUK8RgWoDB0u8tZ6ooYcane_hUpV9lTMSzLHzymaNN6_lk_y7M9hvZGzbAhGZa6nZqKt\n" +
                "ZKFpMq4X-q201kP7amW4gyYiAojOuuUvHPLP3zKo2zSa-I14jTWTK7ZA3WK1NqhlBKCRRe8ZPpDjYJMjKt1OhMmYFgoW3_O0HKRCXX8HFydCtVCQdFfMVwWpYhtCV-XWtxkCeD6X_A";

        JWT jwt = JWTParser.parse(jwtToken);

        Assert.assertTrue(!jwt.getJWTClaimsSet().getClaims().isEmpty());

    }


}
