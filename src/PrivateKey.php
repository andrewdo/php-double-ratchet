<?php
declare(strict_types=1);

namespace DoubleRatchet;

use deemru\Curve25519;

class PrivateKey extends Key
{
    /**
     * @param string $value
     */
    public function __construct(string $value)
    {
        // https://cr.yp.to/ecdh.html
        $value[0]  = chr(ord($value[0])  & 0b11111000);
        $value[31] = chr(ord($value[31]) & 0b10010011);
        $value[31] = chr(ord($value[31]) | 0b01000000);

        parent::__construct($value);
    }

    /**
     * @param string $dataToSign
     * @return string
     */
    public function getSignature(string $dataToSign) : string
    {
        return (new Curve25519())->sign($dataToSign, $this->getValue());
    }
}
