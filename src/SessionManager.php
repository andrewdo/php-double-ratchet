<?php

namespace DoubleRatchet;

use Assert\Assert;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function Curve25519\sharedKey;
use deemru\Curve25519;
use Exception;

class SessionManager
{
    /** The json key name to use when sending/receiving ratchet keys */
    const DEFAULT_RATCHET_DATA_KEY = 'ratchet_key';
    const HASHING_ALGORITHM = 'sha256';
    const ENCRYPTION_ALGORITHM = 'aes-256-cbc';

    /** @var KeyPair */
    private $ourIdentity;
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
    /** @var string */
    private $ratchetDataKey;

    /**
     * @param Key $ourPrivateKey
     * @param Key $theirPublicKey
     * @param Key $preKeyPublicKey
     * @param Key|null $preKeyPrivateKey if given, assumes we are receiving the session create message
     * @param LoggerInterface $logger
     * @param array<string|mixed> $options
     * @throws Exception
     */
    public function __construct(
        Key $ourPrivateKey,
        Key $theirPublicKey,
        Key $preKeyPublicKey,
        Key $preKeyPrivateKey = null,
        LoggerInterface $logger = null,
        array $options = []
    ) {
        $this->logger = $logger === null ? new NullLogger() : $logger;

        $this->ourIdentity = new KeyPair($ourPrivateKey);
        $this->theirPublicKey = $theirPublicKey;

        // generate root key
        if ($preKeyPrivateKey === null) {
            $secret1 = sharedKey($this->ourIdentity->getPrivateKey()->getValue(), $theirPublicKey->getValue());
            $secret2 = sharedKey($this->ourIdentity->getPrivateKey()->getValue(), $preKeyPublicKey->getValue());
        } else {
            $secret1 = sharedKey($preKeyPrivateKey->getValue(), $preKeyPublicKey->getValue());
            $secret2 = sharedKey($this->ourIdentity->getPrivateKey()->getValue(), $theirPublicKey->getValue());
        }

        $this->rootKey = sharedKey($secret1, $secret2);

        $this->logger->debug('Generated secret1: ' . $secret1);
        $this->logger->debug('Generated secret2: ' . $secret2);
        $this->logger->debug('Generated root key: ' . $this->rootKey);

        $this->ratchetDataKey = array_key_exists('ratchet_data_key', $options)
            ? $options['ratchet_data_key']
            : self::DEFAULT_RATCHET_DATA_KEY;

        $this->getNextChainKey();
    }

    /**
     * @param Key $key
     * @return Key
     */
    public function getKeySignature(Key $key) : Key
    {
        $curve25519 = new Curve25519();
        Assert::that(strlen($key))
            ->eq(32, 'Key to sign must be 32 bytes');

        return new Key($curve25519->sign($key, $this->ourIdentity->getPrivateKey()->getValue()));
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
            $this->lastRatchetKey = KeyPair::getNewKeyPair();

            $data[$this->ratchetDataKey] = $this->lastRatchetKey->getPublicKey();
        }

        // the first ratchet
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
        if ($this->lastRatchetKey !== null && !property_exists($data, $this->ratchetDataKey)) {
            throw new Exception('Missing ratchet key in message');
        }

        if ($this->lastRatchetKey !== null) {
            $this->ratchetRootKey(new Key($data->{$this->ratchetDataKey}));
        }

        return $data;
    }

    /**
     * @param Key $theirRatchetPublicKey
     */
    private function ratchetRootKey(Key $theirRatchetPublicKey) : void
    {
        $ratchetSecret = sharedKey($this->lastRatchetKey->getPrivateKey(), $theirRatchetPublicKey->getValue());
        Assert::that(strlen($ratchetSecret))
            ->eq('32', 'Shared ratchet secret must be 32 bytes');

        $this->rootKey = hash(self::HASHING_ALGORITHM, $ratchetSecret);

        $this->getNextChainKey();
    }
}
