[![Tests](https://github.com/marguskaidja/php-openssl-wrapper/actions/workflows/tests.yml/badge.svg)](https://github.com/marguskaidja/php-openssl-wrapper/actions/workflows/tests.yml)

# PHP OpenSSL wrapper
Object Oriented wrapper around PHP OpenSSL extension

## Problems that this library solves
The interface of PHP's OpenSSL extension is archaic and can only be used procedural way, which makes it awkward to use and requires excessive code to handle errors and results. This library tries to solve following shortcomings:
* **Errors are not handled using Exceptions**: The failures should be always reported using Exceptions instead of procedural way by returning `false` or `-1`.
* **Unexpected PHP warnings**: PHP OpenSSL functions should not emit PHP warnings. All warnings should be silently collected and handed over using Exception or through return value. This way the caller can programmatically decide, how to handle them (e.g. log warnings to specific place).
* **Function outcome not in return value**: The (primary) result that OpenSSL function produces should also be the return value, instead of returning result through one of the function arguments (e.g. `openssl_sign`). The best examples of awkwardness are `openssl_seal` or `openssl_csr_new` which both return values inside multiple input parameters.
* **Key/Certificate/CSR objects are just numb internal DTO-s**: Although in PHP 8 the OpenSSL resources were replaced with objects (`OpenSSLCertificate`, `OpenSSLCertificateSigningRequest` and `OpenSSLAsymmetricKey`), they are internally still just plain DTO-s (Data Transfer Objects). There's no methods or properties exposed and they can only be used in procedural way by specifying it as parameter to one of the `openssl_*` functions. This library wraps those objects to provide direct access to OpenSSL methods specific to the object.

The functionality with extension is almost fully retained, which means that all internal `openssl_*` functions (except deprecated or duplicates) are wrapped. Difference lies between method signatures: wrapper signatures can be shorter and it's parameters are never specified by reference.

What this library doesn't do: **it doesn't add or change any of the OpenSSL cryptographic functionality**. The only purpose is to just offer convenient object oriented interface for OpenSSL functions.

## Requirements

* PHP >= 8.0
* [OpenSSL Extension](https://www.php.net/manual/en/book.openssl.php)

## Installation

Install with composer:
```bash
composer require margusk/openssl-wrapper
```

## Usage

### Static methods vs instance methods
Wrapper can be used in 2 different ways:
1. **Statically**: the simplest way is to use static [`OpenSSL`](src/OpenSSL.php) class:
```php
use margusk\OpenSSL\Wrapper\OpenSSL;

$result = OpenSSL::pkeyNew([
  'private_key_type' => OPENSSL_KEYTYPE_RSA
]);
````
2. Using **instance**: to have ability to customize/intercept exceptions, use [`Proxy`](src/Proxy.php) instance (see below for Customizing/intercepting exceptions):
```php
use margusk\OpenSSL\Wrapper\Proxy as OpenSSLProxy;

$proxy = new OpenSSLProxy();

$result = $proxy->pkeyNew([
   'private_key_type' => OPENSSL_KEYTYPE_RSA
]);
````

### Mapping OpenSSL function to wrapper method name
Most of the OpenSSL functions have counterparts in wrapper class (but see exceptions below).

Wrapper name can be derived as following:
1. Remove `openssl_` prefix from internal function name
2. Convert the remainder from snake-case into camel-case format

E.g. `openssl_get_cipher_methods` transforms to `getCipherMethods` and can be called using:
* `OpenSSL::getCipherMethods()` or
* `(new OpenSSLProxy())->getCipherMethods()`

Following functions are not wrapped:
* [`openssl_free_key`](https://www.php.net/manual/en/function.openssl-free-key.php) - deprecated in PHP 8
* [`openssl_pkey_free`](https://www.php.net/manual/en/function.openssl-pkey-free.php) - deprecated in PHP 8
* [`openssl_x509_free`](https://www.php.net/manual/en/function.openssl-x509-free.php) - deprecated in PHP 8
* [`openssl_get_privatekey`](https://www.php.net/manual/en/function.openssl-get-privatekey.php) - use [`openssl_pkey_get_private`](https://www.php.net/manual/en/function.openssl-pkey-get-private.php) instead
* [`openssl_get_publickey`](https://www.php.net/manual/en/function.openssl-get-publickey.php) - use [`openssl_pkey_get_public`](https://www.php.net/manual/en/function.openssl-pkey-get-public.php) instead

___

### Return values

Each call to wrapper method returns object derived from [`Result`](src/Result.php) class.

This object encapsulate everything associated with the call from the start to the end. Namely:
* `$result->value()` returns the actual value of the result. The data type depends of the called method and can be `int`, `bool`, `string`, `array` or complex type like [`AsymmetricKey`](src/Parameter/AsymmetricKey.php), [`CSR`](src/Parameter/CSR.php) or [`Certificate`](src/Parameter/Certificate.php)
* `$result->inParameters()` returns array of input parameters for internal function call. Note that optional parameters are always provided
* `$result->outParameters()` returns array of parameters after beeing possibly modified by internal function
* `$result->warnings()->openSSL()` returns array of the warnings reported by OpenSSL library during the call
* `$result->warnings()->php()` returns array of warnings/errors reported by PHP (by emitting warnings) during the call

Some internal functions return values also through referenced input parameters. Wrapper doesn't take such parameters, but returns those values in [`Result`](src/Result.php) object:
1. [`openssl_csr_new`](https://www.php.net/manual/en/function.openssl-csr-new.php): internally generated _&$private_key_ can be received using `$result->privateKey()`
2. [`openssl_encrypt`](https://www.php.net/manual/en/function.openssl-encrypt.php): internally generated _&$tag_ value  can be received using `$result->tag()`
3. [`openssl_random_pseudo_bytes`](https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php): flag of _&$strong_result_ can be received using `$result->strongResult()`
4. [`openssl_seal`](https://www.php.net/manual/en/function.openssl-seal.php): internally generated _&$encrypted_keys_ and _&$iv_ can be received using `$result->encryptedKeys()` and `$result->iv()`

#### Complex types like OpenSSLAsymmetricKey, OpenSSLCertificateSigningRequest and OpenSSLCertificate

Some functions (e.g. [`openssl_pkey_new`](https://www.php.net/manual/en/function.openssl-pkey-new.php)) return special OpenSSL objects, which unfortunately are totally useless on their own. This library makes them a bit more useful. So each time an `openssl_*` function returns an object:
* `OpenSSLAsymmetricKey` is wrapped by [`AsymmetricKey`](src/Parameter/AsymmetricKey.php)
* `OpenSSLCertificateSigningRequest` is wrapped by [`CSR`](src/Parameter/CSR.php)
* `OpenSSLCertificate` is wrapped by [`Certificate`](src/Parameter/Certificate.php)

All those object wrappers provide methods related to the type of OpenSSL object. For example:
* [`AsymmetricKey`](src/Parameter/AsymmetricKey.php) object has `openssl_pkey_*` methods covered
* [`CSR`](src/Parameter/CSR.php) object has `openssl_x509_*` methods covered
* [`Certificate`](src/Parameter/Certificate.php) object has `openssl_csr_*` methods covered

___

### Handling Exceptions

When internal `openssl_*` function fails under the hood, exception [`OpenSSLCallFailedException`](src/Exception/OpenSSLCallFailedException.php) is thrown by default. This special exception carries the specifics of the failure for later inspection. Namely:
* `$exception->funcName()` returns the name of internal function
* `$exception->result()` returns the exact result code of internal function
* `$exception->errors()->openSSL()` returns array of the warnings/errors reported by OpenSSL library
* `$exception->errors()->php()` returns array of warnings/errors reported by PHP (by emitting warnings)

#### Customizing/intercepting exceptions

Sometimes it's nesseccary to provide customized exceptions instead of built-in [`OpenSSLCallFailedException`](src/Exception/OpenSSLCallFailedException.php). There's couple of ways for doing it.

The simplest would be to just put the call inside `try/catch` block and then re-throw with custom exception like this:

```php
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\OpenSSL;

class MyCustomException extends Exception {}

try {
    $pkey = OpenSSL::pkeyNew([
        'private_key_type' => OPENSSL_KEYTYPE_RSA
    ])->value();
} catch (OpenSSLCallFailedException $e) {
    throw new MyCustomException('Something went wrong', 0, $e);
}
```

However, to provide more flexible way of intercepting failures (e.g. for logging), we can register failure handler and associate it with specific or anykind of `openssl_*` function:

```php
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\Proxy as OpenSSLProxy;
use margusk\OpenSSL\Wrapper\Proxy\Options as OpenSSLProxyOptions;

class MyCustomException extends Exception
{
    // ...
}

function myLoggingFunc(string $msg)
{
    // ...
}

// Create Proxy options and register failure handler for "openssl_pkey_new"
$options = (new OpenSSLProxyOptions())
    ->registerFailureHandler('openssl_pkey_new', function(OpenSSLCallFailedException $exception): Throwable {
        myLoggingFunc($exception->funcName() . ': ' $exception->getMessage());

        return new MyCustomException(
            $exception->getMessage(), 
            $exception->getCode(), 
            $exception
        );
   });

// Create private wrapper instance
$proxy = new OpenSSLProxy($options);

// If openssl_pkey_new fails, then error is logged and MyOpenSSLException is thrown instead of OpenSSLCallFailedException
try {
    $pkey = $proxy->pkeyNew([
      'private_key_type' => OPENSSL_KEYTYPE_RSA
    ])->value();
} catch (MyCustomException $e) {
    echo "MyCustomException: " . $e->getMessage() . "\n";
}
```

Failure handler is registered using `OpenSSLProxyOptions::registerFailureHandler(string $pattern, Closure $cb)` where:
* _$pattern_ denotes internal function name for which the handler is executed. If prefixed with **regex:** then the remainder is interpreted as regular expression.
   
   E.g. **regex:openssl_.*** or **regex:.*** will catch all `openssl_*` functions that fail
* _$cb_ is callback accepting 1 parameter of `OpenSSLCallFailedException` and returning `Throwable`. It's also totally okay to throw directly from the callback without returning anything.

Note that `OpenSSLProxyOptions` is immutable class, where each call to `registerFailureHandler` returns cloned instance of itself with new handler added.

To register multiple handlers at once without cloning and throwing away lots of objects for nothing use `OpenSSLProxyOptions::registerFailureHandlers(array $callbacks)`, where `$callbacks` contains `$pattern` and `$cb` parameters in associative way:
```php
use margusk\OpenSSL\Wrapper\Proxy\Options as OpenSSLProxyOptions;
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;

// Register specific handler for "openssl_pkey_new" and another handler for the rest of "openssl_*" functions
$options = (new OpenSSLProxyOptions())
    ->registerFailureHandlers([
        'openssl_pkey_new' => function(OpenSSLCallFailedException $exception): Throwable {
            myLoggingFunc1($exception->funcName() . ': ' $exception->getMessage());

            return new MyCustomException(
                $exception->getMessage(), 
                $exception->getCode(), 
                $exception
           );
        },
        
        'regex:openssl_.*' => function(OpenSSLCallFailedException $exception): Throwable {
            myLoggingFunc2($exception->funcName() . ': ' $exception->getMessage());
            return $exception;
        }
    ]);
```

## License
This library is released under the MIT License.
