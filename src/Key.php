<?php

namespace DoubleRatchet;

use Assert\Assert;
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
