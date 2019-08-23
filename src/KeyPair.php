<?php

use Assert\Assert;
use function Curve25519\publicKey;
use function Curve25519\sharedKey;

class KeyPair
{
    /** @var Key */
    private $privateKey;
    /** @var Key */
    private $publicKey;

    /**
     * @param Key|null $privateKey
     * @param Key|null $publicKey
     * @throws Exception
     */
    public function __construct(Key $privateKey = null, Key $publicKey = null)
    {
        if ($privateKey === null) {
            $privateKey = Key::getNewPrivateKey();
        }

        $this->privateKey = $privateKey;
        Assert::that(strlen($this->privateKey->getValue()))
            ->eq(32, 'Private key must be 32 bytes');

        if ($publicKey === null) {
            $publicKey = new Key(publicKey($this->privateKey->getValue()));
        }
        $this->publicKey = $publicKey;
        Assert::that(strlen($this->publicKey->getValue()))
            ->eq(32, 'Public key must be 32 bytes');
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
