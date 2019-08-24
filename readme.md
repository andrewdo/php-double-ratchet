## Overview
This is a library that handles encryption of messages passed back and forth between two parties,
using a "double ratchet" algorithm. It uses Curve25519 for generating keys and signing.

## Requirements
- PHP 7.1.3 or greater

## Installation
`composer require andrewdo/php-double-ratchet`

## Usage
First thing you'll want to do is either generate or load up your identity private key:

```php
// generate random private key
$ourIdentity = KeyPair::getNewKeyPair();

// load from a base64 string
$ourIdentity = new KeyPair(new PrivateKey(base64_decode($base64String)));
```

In order to start a session with another party, you'll need a signed `Pre Key` from them.
Signature verification is optional but suggested. You should probably also hard code the other
party's public key if you know it ahead of time.

```php
$theirPublicKey = new Key(...their 32 byte public key...);
$theirPreKeyPublicKey = new Key(...their 32 byte pre key public key...);
$theirPreKeySignature = ...signature of the pre key...;
if (!$theirPublicKey->isValidSignature($theirPreKeySignature, $theirPreKey->getValue())) {
    throw new Exception('Sketchy...');
} 
```

Then you can create a `SessionManager` instance.

**NOTE:** If you are the one that generated the `Pre Key` and you have its private key, you will need to pass it along.
```php
$sessionManager = new SessionManager(
    $ourIdentity->getPrivateKey(),
    $theirPublicKey,
    $theirPreKeyPublicKey,
    $preKeyPrivateKey ?: null,  // if we are the receiver of the first message
    $logger ?: null,
    $options ?: []
);
```

The session manager will handle encryption and decryption of JSON payloads, along with the double ratcheting of keys.
It will include the Ratchet Key in each JSON request/response. By default, the key for this field is ratchet_key but can be changed
using the options parameter of the SessionManager.

```php
$encryptedMessageStr = $sessionManager->encryptData(['grandmas_cookbook' => '...']);
$decryptedData = $sessionManager->decryptMessage($encryptedMessageStr);
// var_dump($decryptedData)
// array(2) { ["ratchet_key"]=> string(4) "asdf" ["grandmas_cookbook"]=> ... }
```

If you need to persist the `SessionManager` instance, you can use:
```php
$sessionManagerString = $sessionManager->getAsEncryptedString();
// var_dump($sessionManagerString)
// string(2801) "/6Iq=...A==:eoNnkPa2sCE0F8ezC9TJzA=="

$sessionManager = SessionManager::getFromEncryptedString(
    $ourIdentity->getPrivateKey(),
    $sessionManagerString
);
```

### Generating Pre Keys
In order to receive an ecrypted message from someone, you will need to somehow give them your public key and a signed Pre Key.
To generate one:
```php
$preKey = KeyPair::getNewKeyPair();
$preKeyPublicKey = $preKey->getPublicKey();
$signature = $ourIdentity->getSignature($preKeyPublicKey->getValue());
```

