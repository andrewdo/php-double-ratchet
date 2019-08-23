<?php
declare(strict_types=1);

namespace Tests;

use Assert\AssertionFailedException;
use DoubleRatchet\Key;
use DoubleRatchet\KeyPair;
use PHPUnit\Framework\TestCase;

final class KeyTest extends TestCase
{
    public function testKeyErrorsOnTooShortKey()
    {
        $tooShort = openssl_random_pseudo_bytes(31);

        self::expectException(AssertionFailedException::class);
        self::expectExceptionMessage('Key must be 32 bytes');
        new Key($tooShort);

        self::expectException(AssertionFailedException::class);
        self::expectExceptionMessage('Key must be 32 bytes');
    }

    public function testKeyErrorsOnTooLongKey()
    {
        $tooShort = openssl_random_pseudo_bytes(33);

        self::expectException(AssertionFailedException::class);
        self::expectExceptionMessage('Key must be 32 bytes');
        new Key($tooShort);
    }

    public function testKeyHoldsValue()
    {
        $keyValue = openssl_random_pseudo_bytes(32);
        $key = new Key($keyValue);

        self::assertEquals($keyValue, $key->getValue());
    }

    public function testIsSignatureValidReturnsFalseOnInvalidSignature()
    {
        $key = new Key(openssl_random_pseudo_bytes(32));
        $signature = random_bytes(random_int(32, 64));
        $message = random_bytes(random_int(32, 64));

        self::assertFalse($key->isSignatureValid($signature, $message));
    }

    public function testIsSignatureValidReturnsTrueOnValidSignature()
    {
        $identity = KeyPair::getNewKeyPair();
        $key = new Key($identity->getPublicKey()->getValue());
        $message = random_bytes(random_int(32, 64));
        $signature = $identity->getSignature($message);

        self::assertTrue($key->isSignatureValid($signature, $message));
    }

    public function testToStringReturnsBase64String()
    {
        $keyValue = openssl_random_pseudo_bytes(32);
        $key = new Key($keyValue);

        self::assertEquals(base64_encode($keyValue), $key->__toString());
    }

    public function testKeyIsJsonSerializedAsBase64String()
    {
        $keyValue = openssl_random_pseudo_bytes(32);
        $key = new Key($keyValue);

        self::assertEquals(json_encode(base64_encode($keyValue)), json_encode($key));
    }
}
