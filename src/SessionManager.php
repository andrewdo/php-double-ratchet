<?php
declare(strict_types=1);

namespace DoubleRatchet;

use Assert\Assert;
use DoubleRatchet\Exceptions\DecryptionFailedException;
use DoubleRatchet\Exceptions\EncryptionFailedException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use function Curve25519\sharedKey;
use deemru\Curve25519;
use Exception;
use LogicException;
use stdClass;
use ReflectionClass;

/**
 * For each message, generate a new Message Key by hashing the Chain Key, then updating the Chain Key with its hash
 * There are 2 cases where we need to ratchet the Root Key of the session:
 * CASE_1 - we just sent a message with a ratchet key, after we have received a ratchet key from the other party
 * CASE_2 - we just received a message with a ratchet key, after we have set a ratchet key to other party
 */
final class SessionManager
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
    private $lastSentRatchetKey;
    /** @var Key|null */
    private $lastReceivedRatchetPublicKey;
    /** @var string */
    private $ratchetDataKey;

    /**
     * @param PrivateKey $ourPrivateKey
     * @param Key $theirPublicKey
     * @param Key $preKeyPublicKey
     * @param Key|null $preKeyPrivateKey if given, assumes we are receiving the session create message
     * @param LoggerInterface $logger
     * @param array<string|mixed> $options
     * @throws Exception
     */
    public function __construct(
        PrivateKey $ourPrivateKey,
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
            // initiator... does not know Pre Key private key
            $secret1 = sharedKey($this->ourIdentity->getPrivateKey()->getValue(), $theirPublicKey->getValue());
            $secret2 = sharedKey($this->ourIdentity->getPrivateKey()->getValue(), $preKeyPublicKey->getValue());
        } else {
            // receiver... generated the Pre Key so knows private key
            $secret1 = sharedKey($this->ourIdentity->getPrivateKey()->getValue(), $theirPublicKey->getValue());
            $secret2 = sharedKey($preKeyPrivateKey->getValue(), $theirPublicKey->getValue());

            $this->logger->debug('PreKey private: ' . $preKeyPrivateKey);
        }

        $this->rootKey = new Key(sharedKey($secret1, $secret2));

        $this->logger->debug('PreKey public: ' . $preKeyPublicKey);
        $this->logger->debug('Generated secret1: ' . base64_encode($secret1));
        $this->logger->debug('Generated secret2: ' . base64_encode($secret2));
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
        // TODO: send chain and sequence number to handle out of order messages
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

        $payload = $encrypted . ':' . base64_encode($iv);

        // include HMAC
        return $payload . ':' . base64_encode(hash_hmac(self::HASHING_ALGORITHM, $payload, $secret->getValue()));
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
                ->eq(3, 'Message must include encrypted string, IV and HMAC values');

            $decrypted = openssl_decrypt(
                $parts[0],
                self::ENCRYPTION_ALGORITHM,
                $secret->getValue(),
                0,
                base64_decode($parts[1])
            );
            Assert::that($decrypted)
                ->notEq(false, 'Unable to decrypt message');

            // verify HMAC value
            $payload = implode(':', array_slice($parts, 0, 2));
            $calculatedHmac = base64_encode(hash_hmac(self::HASHING_ALGORITHM, $payload, $secret->getValue()));

            Assert::that($calculatedHmac)
                ->eq($parts[2], 'HMAC value must match');
        } catch (Exception $e) {
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
        $this->previousChainKey = $this->chainKey;

        $this->chainKey = new Key(hash(self::HASHING_ALGORITHM, $this->rootKey->getValue(), true));

        return $this->chainKey;
    }

    /**
     * @return Key
     */
    private function getNextMessageKey() : Key
    {
        $this->previousChainKey = $this->chainKey;

        $messageKey = new Key(hash(self::HASHING_ALGORITHM, $this->chainKey->getValue(), true));
        $this->chainKey = new Key(hash(self::HASHING_ALGORITHM, $this->chainKey->getValue(), true));

        return $messageKey;
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
        if ($this->lastSentRatchetKey === null) {
            $this->lastSentRatchetKey = KeyPair::getNewKeyPair();

            $data[$this->ratchetDataKey] = $this->lastSentRatchetKey->getPublicKey()->__toString();
        }

        // the first ratchet
        try {
            $messageKey = $this->getNextMessageKey();
            $encryptedMessage = $this->encrypt($messageKey, json_encode($data));

            // handle double ratchet CASE_1
            if ($this->lastReceivedRatchetPublicKey !== null && $this->lastSentRatchetKey !== null) {
                $this->ratchetRootKey(
                    $this->lastSentRatchetKey->getPrivateKey(),
                    $this->lastReceivedRatchetPublicKey
                );

                $this->lastSentRatchetKey = null;
                $this->lastReceivedRatchetPublicKey = null;
            }
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
        $messageKey = $this->getNextMessageKey();
        try {
            $decrypted = $this->decrypt($messageKey, $encryptedMessage);

            $data = json_decode($decrypted);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception('Decrypted message failed json_decode with error ' . json_last_error_msg());
            }

            // check for ratchet key, if needed
            $receivedRatchetPublicKey = property_exists($data, $this->ratchetDataKey)
                ? new Key($data->{$this->ratchetDataKey})
                : null;
            if ($this->lastReceivedRatchetPublicKey === null && $receivedRatchetPublicKey === null) {
                throw new Exception('Missing ratchet key in message');
            } else if ($this->lastReceivedRatchetPublicKey !== null
                && $this->lastReceivedRatchetPublicKey->getValue() !== $receivedRatchetPublicKey->getValue()
            ) {
                throw new Exception('Received new ratchet key in response without processing last ratchet key');
            }

            // handle double ratchet CASE_2
            if ($this->lastSentRatchetKey !== null) {
                $this->ratchetRootKey(
                    $this->lastSentRatchetKey->getPrivateKey(),
                    $receivedRatchetPublicKey
                );

                $this->lastSentRatchetKey = null;
            } else if ($receivedRatchetPublicKey !== null) {
                $this->lastReceivedRatchetPublicKey = $receivedRatchetPublicKey;
            }
        } catch (Exception $e) {
            $this->usePreviousChainKey();

            throw $e;
        }

        return $data;
    }

    /**
     * @param Key $ourRatchetPrivateKey
     * @param Key $theirRatchetPublicKey
     */
    private function ratchetRootKey(Key $ourRatchetPrivateKey, Key $theirRatchetPublicKey) : void
    {
        $ratchetSecret = sharedKey($ourRatchetPrivateKey->getValue(), $theirRatchetPublicKey->getValue());
        $this->logger->debug(base64_encode($ratchetSecret));
        Assert::that(strlen($ratchetSecret))
            ->eq('32', 'Shared ratchet secret must be 32 bytes');

        $this->rootKey = new Key(hash(self::HASHING_ALGORITHM, $this->rootKey->getValue() . $ratchetSecret, true));

        $this->getNextChainKey();
    }

    /**
     * @return string
     * @throws Exception
     */
    public function getAsEncryptedString() : string
    {
        return $this->encrypt($this->ourIdentity->getPrivateKey(), serialize(get_object_vars($this)));
    }

    /**
     * @param Key $secret
     * @param string $encryptedAndSerialized
     * @return self
     * @throws Exception
     */
    public static function getFromEncryptedString(Key $secret, string $encryptedAndSerialized) : self
    {
        $decrypted = self::decrypt($secret, $encryptedAndSerialized);
        $data = unserialize($decrypted);
        if (!is_array($data)) {
            throw new Exception('Invalid unserialized data');
        }

        $reflection = new ReflectionClass(self::class);
        $newSelf = $reflection->newInstanceWithoutConstructor();
        foreach ($data as $key => $value) {
            if (property_exists($newSelf, $key)) {
                $newSelf->$key = $value;
            }
        }

        if ($newSelf === false || !$newSelf instanceof self) {
            throw new Exception('Failed to unserialize SessionManager');
        }

        return $newSelf;
    }
}
