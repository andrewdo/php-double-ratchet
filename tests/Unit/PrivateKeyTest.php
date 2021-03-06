<?php
declare(strict_types=1);

namespace Tests;

use DoubleRatchet\PrivateKey;
use PHPUnit\Framework\TestCase;

final class PrivateKeyTest extends TestCase
{
    public function testGetNewKeyPairFormatsPrivateKey()
    {
        // build a key with all the bits set to 0/1 so that should get flipped
        $privateKeyValue = openssl_random_pseudo_bytes(32);
        $privateKeyValue[0]  = chr(ord($privateKeyValue[0])  | 0b00000111);
        $privateKeyValue[31] = chr(ord($privateKeyValue[31]) | 0b01101100);
        $privateKeyValue[31] = chr(ord($privateKeyValue[31]) & 0b01111111);

        $newPrivateKey = new PrivateKey($privateKeyValue);

        // verify it clears and sets all the right bits
        self::assertEquals(ord($newPrivateKey->getValue()[0])  & 0b00000111, 0);
        self::assertEquals(ord($newPrivateKey->getValue()[31]) & 0b00101100, 0);
        self::assertEquals(ord($newPrivateKey->getValue()[31]) & 0b00101100, 0);
        self::assertEquals(ord($newPrivateKey->getValue()[31]) & 0b01000000, 64);
    }
}
