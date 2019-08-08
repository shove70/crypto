import std.conv: to;
import std.stdio;

import crypto.rsa;

void main(string[] argv)
{
    int bits = 1024;

    if (argv.length > 1)
    {
        try
        {
            bits = argv[1].to!int;
        }
        catch(Throwable)
        {
            writeln("Parameter " ~ argv[1] ~ " error. Usage: 128 | 256 | 512 | 1024 | 2048 ...");
            return;
        }

        if (bits < 128)
        {
            writeln("Parameter " ~ argv[1] ~ " too small and needs 128 minimum.");
            return;
        }
    }

    RSAKeyPair keyPair = RSA.generateKeyPair(bits);
    writeln("PrivateKey:");
    writeln(keyPair.privateKey);
    writeln("\r\nPublicKey:");
    writeln(keyPair.publicKey);
}
