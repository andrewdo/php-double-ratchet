<?php
declare(strict_types=1);

namespace Tests;

use DoubleRatchet\Exceptions\DecryptionFailedException;
use DoubleRatchet\KeyPair;
use DoubleRatchet\PrivateKey;
use DoubleRatchet\SessionManager;
use PHPUnit\Framework\TestCase;
use Faker\Generator;
use Faker\Factory;

final class SessionManagerTest extends TestCase
{
    /** @var SessionManager */
    private $serverSessionManager;
    /** @var SessionManager */
    private $clientSessionManager;
    /** @var KeyPair */
    private $serverIdentity;
    /** @var KeyPair */
    private $clientIdentity;
    /** @var Generator */
    private $faker;

    /**
     * @throws \Exception
     */
    public function setUp()
    {
        parent::setUp();

        $this->serverIdentity = KeyPair::getNewKeyPair();
        $this->clientIdentity = KeyPair::getNewKeyPair();
        $preKey = KeyPair::getNewKeyPair();

        $this->serverSessionManager = new SessionManager(
            $this->serverIdentity->getPrivateKey(),
            $this->clientIdentity->getPublicKey(),
            $preKey->getPublicKey(),
            $preKey->getPrivateKey()
        );

        $this->clientSessionManager = new SessionManager(
            $this->clientIdentity->getPrivateKey(),
            $this->serverIdentity->getPublicKey(),
            $preKey->getPublicKey()
        );

        $this->faker = Factory::create();
    }

    public function testDecryptMessageRequiresEncryptedStringIVAndHmac()
    {
        self::expectException(DecryptionFailedException::class);
        self::expectExceptionMessage('Message must include encrypted string, IV and HMAC values');

        $this->serverSessionManager->decryptMessage('missing everything');

        self::expectException(DecryptionFailedException::class);
        self::expectExceptionMessage('Message must include encrypted string, IV and HMAC values');

        $this->serverSessionManager->decryptMessage('some_encrypted_string:some_iv');
    }

    public function testHandlesInvalidMessage()
    {
        $badSecret = new PrivateKey(str_pad('', 32, "\0"));
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $invalidMessage = openssl_encrypt(
            $this->faker->sentence,
            'aes-256-cbc',
            $badSecret->getValue(),
            0,
            $iv
        );
        $invalidMessage = $invalidMessage . ':' . base64_encode($iv);
        $invalidMessage = $invalidMessage . ':' . base64_encode(hash_hmac('sha256', $invalidMessage, $badSecret->getValue()));
        self::expectException(DecryptionFailedException::class);
        self::expectExceptionMessage('Unable to decrypt message');

        $this->serverSessionManager->decryptMessage($invalidMessage);
    }

    public function testSerialRequestResponses()
    {
        for ($i = 0; $i < 50; $i++) {
            $requestData = [$this->faker->userName => $this->faker->sentences];
            $responseData = [$this->faker->userName => $this->faker->sentences];

            // request
            $encryptedMessage = $this->clientSessionManager->encryptData($requestData);
            $decryptedData = $this->serverSessionManager->decryptMessage($encryptedMessage);

            self::assertTrue(property_exists($decryptedData, 'ratchet_key'));
            unset($decryptedData->ratchet_key);
            self::assertEquals($requestData, (array)$decryptedData);

            // response
            $encryptedMessage = $this->serverSessionManager->encryptData($responseData);
            $decryptedData = $this->clientSessionManager->decryptMessage($encryptedMessage);

            self::assertTrue(property_exists($decryptedData, 'ratchet_key'));
            unset($decryptedData->ratchet_key);
            self::assertEquals($responseData, (array)$decryptedData);
        }
    }

    public function testGetAsEncryptedString()
    {
        $sessionManager = $this->serverSessionManager;
        $sessionManagerString = $this->serverSessionManager->getAsEncryptedString();

        self::assertEquals(
            $sessionManager,
            SessionManager::getFromEncryptedString($this->serverIdentity->getPrivateKey(), $sessionManagerString)
        );
    }
}
