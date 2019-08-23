<?php

use Assert\Assert;
use function Curve25519\publicKey;
use deemru\Curve25519;

final class PreKey extends Key implements JsonSerializable
{
    private $signature = null;

    public function sign()
    {

    }

    /**
     * @return array
     */
    public function jsonSerialize() : array
    {
        return [
            'key'       => $this,
            'signature' => $this->signature,
        ];
    }
}
