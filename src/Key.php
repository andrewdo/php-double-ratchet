<?php

namespace DoubleRatchet;

use Assert\Assert;
use deemru\Curve25519;
use JsonSerializable;

class Key implements JsonSerializable
{
    /** @var string */
    protected $value;

    /**
     * @param string $value
     */
    public function __construct(string $value)
    {
        $this->value = $value;

        Assert::that(strlen($this->value))
            ->eq(32, 'Key must be 32 bytes');
    }

    /**
     * @return string
     */
    public function getValue() : string
    {
        return $this->value;
    }

    /**
     * @param string $signature
     * @param string $message
     * @return bool
     */
    public function isSignatureValid(string $signature, string $message) : bool
    {
        return (new Curve25519())->verify($signature, $message, $this->getValue());
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return base64_encode($this->getValue());
    }

    /**
     * @return string
     */
    public function jsonSerialize()
    {
        return $this->__toString();
    }
}
