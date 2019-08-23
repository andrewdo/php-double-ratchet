<?php

use Assert\Assert;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function Curve25519\sharedKey;

class SessionManager
{
    /**
     * The json key name to use when sending/receiving ratchet keys
     * @var string
     */
    const RATCHET_DATA_KEY = 'ratchet_key';
    const HASHING_ALGORITHM = 'sha256';
    const ENCRYPTION_ALGORITHM = 'aes-256-cbc';

    /** @var Key */
    private $ourPrivateKey;
    /** @var Key */
    private $theirPublicKey;
    /** @var Key */
    private $rootKey;
    /** @var Key */
    private $chainKey;
    /** @var Key */
    private $messageKey;
    /** @var LoggerInterface */
    private $logger;
    /** @var KeyPair|null */
    private $lastRatchetKey = false;

    /**
     * @param Key $ourPrivateKey
     * @param Key $theirPublicKey
     * @param Key $preKeyPublicKey
     * @param LoggerInterface $logger
     */
    public function __construct(
        Key $ourPrivateKey,
        Key $theirPublicKey,
        Key $preKeyPublicKey,
        LoggerInterface $logger = null
    ) {
        $this->logger = $logger === null ? new NullLogger() : $logger;

        $this->ourPrivateKey = $ourPrivateKey;
        $this->theirPublicKey = $theirPublicKey;

        // generate root key
        $secret1 = sharedKey($this->ourPrivateKey->getValue(), $theirPublicKey->getValue());
        $secret2 = sharedKey($this->ourPrivateKey->getValue(), $preKeyPublicKey->getValue());
        $this->rootKey = sharedKey($secret1, $secret2);

        $this->logger->debug('Generated secret1: ' . $secret1);
        $this->logger->debug('Generated secret2: ' . $secret2);
        $this->logger->debug('Generated root key: ' . $this->rootKey);

        $this->getNextChainKey();
    }

    /**
     * @return Key
     * @throws Exception
     */
    public static function getNewPrivateKey() : Key
    {
        $isStrong = false;
        $privateKey = openssl_random_pseudo_bytes(32, $isStrong);
        if (!$isStrong) {
            throw new Exception('Failed to generate strong random value');
        }

        // https://cr.yp.to/ecdh.html
        $privateKey[0] = chr(ord($privateKey[0]) & 248);
        $privateKey[31] = chr(ord($privateKey[0]) & 147);
        $privateKey[31] = chr(ord($privateKey[0]) | 64);

        return new Key($privateKey);
    }

    /**
     * @return Key
     */
    private function getNextChainKey() : Key
    {
        $this->chainKey = hash('sha-256', $this->rootKey, 0x1);

        return new Key($this->chainKey);
    }

    /**
     * @return Key
     */
    private function getNextMessageKey() : Key
    {
        $this->messageKey = hash('sha-256', $this->chainKey, 0x1);

        return new Key($this->messageKey);
    }

    /**
     * @param array $data
     * @return string
     * @throws Exception
     */
    public function encrypt(array $data) : string
    {
        // send a ratchet key with the first message that is not responded to
        if ($this->lastRatchetKey === null) {
            $this->lastRatchetKey = new KeyPair(self::getNewPrivateKey());

            $data[self::RATCHET_DATA_KEY] = $this->lastRatchetKey->getPublicKey();
        }

        $messageKey = $this->getNextMessageKey();

        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::ENCRYPTION_ALGORITHM));
        $encrypted = openssl_encrypt(json_encode($data), self::ENCRYPTION_ALGORITHM, $messageKey, 0, $iv);
        $encrypted = $encrypted . ':' . base64_encode($iv);

        return $encrypted;
    }

    /**
     * @param string $message
     * @return object
     * @throws Exception
     */
    public function decrypt(string $message) : string
    {
        $parts = explode(':', $message);
        if (count($parts) != 2) {
            throw new Exception('Unexpected payload ' . $message);
        }

        $previousMessageKey = $this->messageKey;
        $messageKey = $this->getNextMessageKey();
        $decrypted = openssl_decrypt($parts[0], 'aes-256-cbc', $messageKey, 0, base64_decode($parts[1]));
        if ($decrypted === false) {
            $this->messageKey = $previousMessageKey;

            throw new Exception('Failed to decrypt message ' . $message);
        }

        $data = json_decode($decrypted);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('Decrypted message failed json_decode with error ' . json_last_error_msg());
        }

        // require a ratchet key if we have sent a message with a ratchet key that was not responded to
        if ($this->lastRatchetKey !== null && !property_exists($data, self::RATCHET_DATA_KEY)) {
            throw new Exception('Missing ratchet key in message');
        }

        if ($this->lastRatchetKey !== null) {
            $this->ratchetChainKey(new Key($data->{self::RATCHET_DATA_KEY}));
        }

        return $data;
    }

    /**
     * @param Key $theirRatchetPublicKey
     */
    private function ratchetChainKey(Key $theirRatchetPublicKey) : void
    {
        $ratchetSecret = sharedKey($this->lastRatchetKey->getPrivateKey(), $theirRatchetPublicKey->getValue());
        Assert::that(strlen($ratchetSecret))
            ->eq('32', 'Shared ratchet secret must be 32 bytes');

        $this->chainKey = hash(self::HASHING_ALGORITHM, $ratchetSecret);
    }
}
