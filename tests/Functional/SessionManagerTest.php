<?php
declare(strict_types=1);

namespace Tests;

use DoubleRatchet\KeyPair;
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
    /** @var Generator */
    private $faker;

    /**
     * @throws \Exception
     */
    public function setUp()
    {
        parent::setUp();

        $serverIdentity = KeyPair::getNewKeyPair();
        $clientIdentity = KeyPair::getNewKeyPair();
        $preKey = KeyPair::getNewKeyPair();

        $this->serverSessionManager = new SessionManager(
            $serverIdentity->getPrivateKey(),
            $clientIdentity->getPublicKey(),
            $preKey->getPublicKey(),
            $preKey->getPrivateKey()
        );

        $this->clientSessionManager = new SessionManager(
            $clientIdentity->getPrivateKey(),
            $serverIdentity->getPublicKey(),
            $preKey->getPublicKey()
        );

        $this->faker = Factory::create();
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
}
