<?php

namespace DoubleRatchet;

use Assert\Assert;
use Assert\AssertionFailedException;
use DoubleRatchet\Exceptions\DecryptionFailedException;
use DoubleRatchet\Exceptions\EncryptionFailedException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function Curve25519\sharedKey;
use deemru\Curve25519;
use Exception;
use stdClass;

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
    private $preKeyPublicKey;
    /** @var Key */
    private $rootKey;
    /** @var Key */
    private $chainKey;
    /** @var Key|null */
    private $previousChainKey;
    /** @var LoggerInterface */
    private $logger;
    /** @var KeyPair|null */
    private $lastRatchetKey;
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
        $this->preKeyPublicKey = $preKeyPublicKey;

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
     * @return KeyPair
     */
    public function getOurIdentity() : KeyPair
    {
        return $this->ourIdentity;
    }

    /**
     * @return Key
     */
    public function getTheirPublicKey() : Key
    {
        return $this->theirPublicKey;
    }

    /**
     * @return Key
     */
    public function getPreKeyPublicKey() : Key
    {
        return $this->preKeyPublicKey;
    }

    /**
     * @param Key $secret
     * @param string $message
     * @return string
     * @throws EncryptionFailedException
     */
    private static function encrypt(Key $secret, string $message) : string
    {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::ENCRYPTION_ALGORITHM));
        $encrypted = openssl_encrypt(
            $message,
            self::ENCRYPTION_ALGORITHM,
            $secret->getValue(),
            0,
            $iv
        );
        if ($encrypted === false) {
            throw new EncryptionFailedException('Failed to encrypt message ' . $message);
        }

        return $encrypted . ':' . base64_encode($iv);
    }

    /**
     * @param Key $secret
     * @param string $message
     * @return string
     * @throws DecryptionFailedException
     */
    private static function decrypt(Key $secret, string $message) : string
    {
        try {
            $parts = explode(':', $message);
            Assert::that(count($parts))
                ->eq(2, 'Message must include IV value');

            $decrypted = openssl_decrypt($parts[0], 'aes-256-cbc', $secret->getValue(), 0, base64_decode($parts[1]));
            Assert::that($decrypted)
                ->notEq(false, 'Unable to decrypt message');
        } catch (AssertionFailedException $e) {
            throw new DecryptionFailedException($e->getMessage());
        }

        return $decrypted;
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
        $this->chainKey = hash(self::HASHING_ALGORITHM, $this->rootKey, 0x1);

        return new Key($this->chainKey);
    }

    /**
     * @return Key
     */
    private function getNextMessageKey() : Key
    {
        $this->previousChainKey = $this->chainKey;

        $messageKey = hash(self::HASHING_ALGORITHM, $this->chainKey, 0x1);
        $this->chainKey = hash(self::HASHING_ALGORITHM, $this->chainKey, 0x2);

        return new Key($messageKey);
    }

    /**
     * @throws Exception
     */
    private function usePreviousChainKey() : void
    {
        if ($this->previousChainKey === null) {
            throw new Exception('Missing previous chain key');
        }

        $this->chainKey = $this->previousChainKey;
    }

    /**
     * @param array $data
     * @return string
     * @throws Exception
     */
    public function encryptData(array $data) : string
    {
        // send a ratchet key with the first message that is not responded to
        if ($this->lastRatchetKey === null) {
            $this->lastRatchetKey = KeyPair::getNewKeyPair();

            $data[$this->ratchetDataKey] = $this->lastRatchetKey->getPublicKey();
        }

        // the first ratchet
        try {
            $messageKey = $this->getNextMessageKey();
            $encryptedMessage = $this->encrypt($messageKey, json_encode($data));
        } catch (EncryptionFailedException $e) {
            $this->usePreviousChainKey();

            throw $e;
        }

        return $encryptedMessage;
    }

    /**
     * @param string $encryptedMessage
     * @return stdClass
     * @throws Exception
     */
    public function decryptMessage(string $encryptedMessage) : stdClass
    {
        $parts = explode(':', $encryptedMessage);
        if (count($parts) != 2) {
            throw new Exception('Unexpected payload ' . $encryptedMessage);
        }

        $messageKey = $this->getNextMessageKey();
        try {
            $decrypted = $this->decrypt($messageKey, $encryptedMessage);

            $data = json_decode($decrypted);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception('Decrypted message failed json_decode with error ' . json_last_error_msg());
            }

            // require a ratchet key if we have sent a message with a ratchet key that was not responded to
            if ($this->lastRatchetKey !== null && !property_exists($data, $this->ratchetDataKey)) {
                throw new Exception('Missing ratchet key in response');
            }

            if ($this->lastRatchetKey !== null) {
                $this->ratchetRootKey(new Key($data->{$this->ratchetDataKey}));
            }
        } catch (Exception $e) {
            $this->usePreviousChainKey();

            throw $e;
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

    /**
     * @return string
     * @throws Exception
     */
    public function getAsSerializedAndEncryptedString() : string
    {
        return $this->encrypt($this->ourIdentity->getPrivateKey(), serialize($this));
    }

    /**
     * @param Key $secret
     * @param string $encryptedAndSerialized
     * @return self
     * @throws Exception
     */
    public static function getFromEncryptedAndSerializedString(
        Key $secret,
        string $encryptedAndSerialized
    ) : self {
        $decrypted = self::decrypt($secret, $encryptedAndSerialized);
        $self = unserialize(
            $decrypted,
            [
                'allowed_classes' => [
                    self::class,
                ]
            ]
        );
        if ($self === false || !$self instanceof self) {
            throw new Exception('Failed to unserialize SessionManager');
        }

        return $self;
    }
}
