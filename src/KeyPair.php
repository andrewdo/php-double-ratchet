<?php

namespace DoubleRatchet;

use Assert\Assert;
use function Curve25519\publicKey;
use function Curve25519\sharedKey;
use deemru\Curve25519;
use Exception;

final class KeyPair
{
    /** @var PrivateKey */
    private $privateKey;
    /** @var Key */
    private $publicKey;

    /**
     * @param PrivateKey $privateKey
     * @param Key|null $publicKey
     * @throws Exception
     */
    public function __construct(PrivateKey $privateKey, Key $publicKey = null)
    {
        $this->privateKey = $privateKey;

        if ($publicKey === null) {
            $publicKey = new Key(publicKey($this->privateKey->getValue()));
        }
        $this->publicKey = $publicKey;
    }

    /**
     * @return self
     * @throws Exception
     */
    public static function getNewKeyPair() : self
    {
        $privateKey = new PrivateKey(openssl_random_pseudo_bytes(32, $isStrong));
        if (!$isStrong) {
            throw new Exception('Failed to generate strong random value');
        }

        return new self($privateKey);
    }

    /**
     * @return Key
     */
    public function getPrivateKey() : Key
    {
        return $this->privateKey;
    }

    /**
     * @return Key
     */
    public function getPublicKey() : Key
    {
        return $this->publicKey;
    }

    /**
     * @param string $dataToSign
     * @return string
     */
    public function getSignature(string $dataToSign) : string
    {
        return (new Curve25519())->sign($dataToSign, $this->getPrivateKey()->getValue());
    }

    /**
     * @param string $signature
     * @param string $message
     * @return bool
     */
    public function isSignatureValid(string $signature, string $message) : bool
    {
        return $this->publicKey->isSignatureValid($signature, $message);
    }

    /**
     * @param Key $theirPublicKey
     * @return string|null
     */
    public function getSharedSecret(Key $theirPublicKey) : ?string
    {
        $sharedKey = sharedKey($this->getPrivateKey()->getValue(), $theirPublicKey->getValue());
        if ($sharedKey !== false) {
            Assert::that(strlen($sharedKey))
                ->eq(32, 'Shared secret generated was not 32 bytes');

            return $sharedKey;
        }

        return null;
    }
}
