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
```php
$theirPublicKey = new Key([their 32 byte public key]);
$theirPreKey = new Key([their 32 byte pre key public key]);
$theirPreKeySignature = [signature of the pre key];
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
    KeyPair::getNewKeyPair()->getPublicKey(),
    $preKeyPrivateKey ?: null,
    $logger ?: null,
    $options ?: []
);
```

The session manager will handle encryption and decryption of JSON payloads, along with the double ratcheting of keys.

If you need to persist the `SessionManager` instance, you can use:
```php
$sessionManagerString = $sessionManager->getAsEncryptedString();
$sessionManager = SessionManager::getFromEncryptedString(
    $ourIdentity->getPrivateKey(),
    $sessionManagerString
);
```

