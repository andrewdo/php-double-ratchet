<?php

namespace DoubleRatchet;

class PrivateKey extends Key
{
    public function __construct(string $value)
    {
        // https://cr.yp.to/ecdh.html
        $value[0]  = chr(ord($value[0])  & 0b11111000);
        $value[31] = chr(ord($value[31]) & 0b10010011);
        $value[31] = chr(ord($value[31]) | 0b01000000);

        parent::__construct($value);
    }
}
