<?php

/**
 * This file is part of the openssl-wrapper package.
 *
 * @author  Margus Kaidja <margusk@gmail.com>
 * @link    https://github.com/marguskaidja/php-openssl-wrapper
 * @license http://www.opensource.org/licenses/mit-license.php MIT (see the LICENSE file)
 */

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Tests;

use margusk\OpenSSL\Wrapper\Proxy as OpenSSLProxy;
use margusk\OpenSSL\Wrapper\Result\AsymmetricKey as AsymmetricKeyResult;
use margusk\OpenSSL\Wrapper\Result\CSRNew as CSRNewResult;
use margusk\OpenSSL\Wrapper\Result\RandomPseudoBytes as RandomPseudoBytesResult;
use margusk\OpenSSL\Wrapper\Result\Seal as SealResult;
use OpenSSLAsymmetricKey;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionExtension;
use ReflectionMethod;

class WrappedMethodsTest extends TestCase
{
    protected string $testPrivateKey = '-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALgsa0i5ihk56YPG
NJhKrnPv18Nu5WkhZAdRLFMB1mxsW6ATPfZlfAkQr10y75khDvPBhW2GN6CF9eq4
nmkgp17HbvqAbPOj0c7KlqmuyotUUPpeuBiT8qrnkgpQSZpN0DgZCeJLvhtPOJeN
H7mS8jCMxrXPy4lDo2uKM/oyV9+hAgMBAAECgYB796IrLIBRJJMS2Mo0LCiq7yjr
amzOy+P5rODJ6rW6+2DdKbaOcJcBvxJbCFsQVpkq5/r40twEl8cEvEocdxdQZxO8
peLRrK4/WwT2jVDr1UWXAA8OpHHcoDAJE3DbwbQOmX1OnKtefnlWVlnqG1zZnJLl
lhBHN8vCcYw3qGomsQJBAOLOcZ03cLomddogRmGQoOBTUQ353b6TO0ejyVPihLpS
HzFxn3NIWnlbxcIZnEqe2HVPJJS0xmbLWDfqySOIb+0CQQDP4Srb9UEVUnDkyM78
VON7c5CkU84kF2HTAd4OASAWotkB5VEC8KjxuCNZLHitPqxIfX3Up/IqLbx8NfPb
znAFAkAbJH+eQ/s+m8mwz/n8RRWrouzpUkTCQNZwTV6TpmEh9x/6h9GAN2F0cpIp
F22H1Jis+Uq0bSntNVqaXoOxt+tFAkBgHb5RYX6sOygTwH1j0mQ0CmUQdedUbLNA
exaO5xpNHRK1e7APafLTgM5nRtatU9MY2V063ERuGCOUUuXj9fl5AkEAuVLFty6S
cyTEfd+Txyl+4sb68YYbc8ecP2ycnOZoXK4EoYLo0GD8YV9YlLGapdIw73J7iYGh
fYiO/RwFocvAJA==
-----END PRIVATE KEY-----';

    protected function toCamelCase(string $name): string
    {
        $name = implode('', array_map(
            function ($l) {return ucfirst($l);},
            explode('_', strtolower($name))
        ));
        $name[0] = strtolower($name[0]);

        return $name;
    }

    protected function getExtensionFunctions(): array
    {
        $result = [];

        foreach ((new ReflectionExtension('openssl'))->getFunctions() as $name => $reflectionFunction) {
            $name = substr($name, strlen('openssl_'));
            $wrapperName = $this->toCamelCase($name);

            if (!in_array(
                $wrapperName,
                ['errorString', 'freeKey', 'pkeyFree', 'x509Free', 'getPrivatekey', 'getPublickey']
            )
            ) {
                $result[$wrapperName] = $reflectionFunction;
            }
        }

        return $result;
    }

    public function test_if_all_openssl_methods_are_wrapped()
    {
        // Collect functions from openssl extension
        $cmp1 = array_keys($this->getExtensionFunctions());

        // Collect methods from openssl-wrapper
        $cmp2 = [];
        foreach (
            (new ReflectionClass(OpenSSLProxy::class))->getMethods(
                ReflectionMethod::IS_PUBLIC
            ) as $method
        ) {
            if (!$method->isStatic() && !$method->isConstructor() && !$method->isDestructor()) {
                $cmp2[] = $method->getName();
            }
        }

        // Remove non-wrapper methods from $cmp2
        $cmp2 = array_filter($cmp2, function ($methodName) use ($cmp1) {
            return in_array($methodName, $cmp1);
        });

        $this->assertEqualsCanonicalizing($cmp1, $cmp2);
    }

    public function test_aes_128_cipher_iv_length_must_be_sixteen()
    {
        $p = new OpenSSLProxy();
        $this->assertEquals(16, $p->cipherIvLength('AES-128-CBC')->value());
    }

    public function test_result_contains_correct_function_name()
    {
        $p = new OpenSSLProxy();
        $result = $p->cipherIvLength('AES-128-CBC');
        $this->assertEquals('openssl_cipher_iv_length', $result->funcName());
    }

    public function test_creating_new_private_key_must_succeed()
    {
        $p = new OpenSSLProxy();

        $nBits = 1024;
        $pkeyResult = $p->pkeyNew([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $nBits
        ]);

        $this->assertInstanceOf(AsymmetricKeyResult::class, $pkeyResult);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $pkeyResult->value()->internal());

        $this->assertEquals(
            openssl_pkey_get_details($pkeyResult->value()->internal()),
            $pkeyResult->value()->pkeyGetDetails()->value()
        );
    }

    public function test_creating_new_csr_key_must_succeed()
    {
        $p = new OpenSSLProxy();

        $pkeyResult = $p->pkeyNew([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 1024
        ]);

        $csrSubject = [
            'C' => 'ee',
            'CN' => 'example.com',
            'ST' => 'some random state',
            'O' => 'Random Organization LLC',
        ];

        $csrResult = $p->csrNew(
            $csrSubject,
            $pkeyResult->value(),
            null
        );

        $this->assertInstanceOf(CSRNewResult::class, $csrResult);
        $this->assertInstanceOf(OpenSSLCertificateSigningRequest::class, $csrResult->value()->internal());

        $this->assertEquals($csrSubject, openssl_csr_get_subject($csrResult->value()->internal()));
        $this->assertEquals($csrSubject, $csrResult->value()->csrGetSubject()->value());

        // Verify that csr is created with the $pkeyResult
        $this->assertEquals(
            openssl_pkey_get_details($csrResult->value()->csrGetPublicKey()->value()->internal())['key'],
            $pkeyResult->value()->pkeyGetDetails()->value()['key']
        );

        $this->assertMatchesRegularExpression(
            '/^-----BEGIN CERTIFICATE REQUEST-----.*-----END CERTIFICATE REQUEST-----/s',
            $csrResult->value()->csrExport()->value()
        );
    }

    public function test_pkcs7_read_must_convert_to_x509_certificate_string()
    {
        $pkcs7Data = '-----BEGIN PKCS7-----
MIICggYJKoZIhvcNAQcCoIICczCCAm8CAQExADALBgkqhkiG9w0BBwGgggJVMIIC
UTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjELMAkG
A1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4x
FDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgxNDIx
MTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJDTjEL
MAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFuZzBc
MA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7jV14q
eyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGjgbEw
ga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaAFFXI
70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UECBMC
UE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDASBgNV
BAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQAD
QQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+JuWm7D
CfrPNGVwFWUQOmsPue9rZBgOoQAxAA==
-----END PKCS7-----
';

        $expectedX509 = '-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC
VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx
NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD
TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu
ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j
V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj
gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA
FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE
CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS
BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE
BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju
Wm7DCfrPNGVwFWUQOmsPue9rZBgO
-----END CERTIFICATE-----
';

        $p = new OpenSSLProxy();

        $certificates = $p->pkcs7Read($pkcs7Data)->value();

        $this->assertIsArray($certificates);
        $this->assertCount(1, $certificates);
        $this->assertArrayHasKey(0, $certificates);
        $this->assertEquals($expectedX509, $certificates[0]);
    }

    public function test_sign_must_correctly_sign_the_given_data()
    {
        $p = new OpenSSLProxy();

        $expectedSignature = '0a1eed4a8dd57b44507154203c1007c412fce2d712da7a4c75b3fcc1533b9c9ef406afef8d3e72838ef029065f4f41b9bd13b33a3550a5a397d273e22ea6d47cfc1253a224ed0ac76cebc4177ae032dd1de19afcb8d02805c543f9a2b0567b3c12ff4a1dab07459bfbe31a28622237658b98f9e8ef13eee044006630b05b467e';

        $pkeyResult = $p->pkeyGetPrivate($this->testPrivateKey);
        $signedData = $pkeyResult->value()->sign('random data to test sign method')->value();

        $this->assertEquals($expectedSignature, bin2hex($signedData));
    }

    public function test_sealed_data_by_lib_must_be_opened_by_using_openssl_ext()
    {
        $data = 'this is secret data';
        $cipherAlgo = 'AES256';

        // Seal the data using library
        $p = new OpenSSLProxy();
        $keyDetails = $p->pkeyGetPrivate($this->testPrivateKey)->value()->pkeyGetDetails()->value();

        $sealResult = $p->seal(
            $data,
            [$keyDetails['key']],
            $cipherAlgo
        );

        $this->assertInstanceOf(SealResult::class, $sealResult);
        $this->assertEquals(openssl_cipher_iv_length($cipherAlgo), strlen($sealResult->iv()));
        $this->assertCount(1, $sealResult->encryptedKeys());
        $this->assertArrayHasKey(0, $sealResult->encryptedKeys());

        // Open data using OpenSSL extension directly
        $decodedData = null;
        openssl_open(
            $sealResult->value(),
            $decodedData,
            $sealResult->encryptedKeys()[0],
            openssl_pkey_get_private($this->testPrivateKey),
            $cipherAlgo,
            $sealResult->iv()
        );

        $this->assertEquals($data, $decodedData);
    }

    public function test_sealed_data_by_openssl_ext_must_be_opened_by_lib()
    {
        $data = 'this is secret data';
        $cipherAlgo = 'AES256';

        // Seal the data using OpenSSL ext
        $sealedData = null;
        $encryptedKeys = [];
        $iv = null;
        openssl_seal(
            $data,
            $sealedData,
            $encryptedKeys,
            [openssl_pkey_get_public(
                openssl_pkey_get_details(
                    openssl_pkey_get_private($this->testPrivateKey)
                )['key']
            )],
            $cipherAlgo,
            $iv
        );

        // Open data using library
        $p = new OpenSSLProxy();

        $decodeResult = $p->open(
            $sealedData,
            $encryptedKeys[0],
            $p->pkeyGetPrivate($this->testPrivateKey)->value(),
            $cipherAlgo,
            $iv
        );

        $this->assertEquals($data, $decodeResult->value());
    }

    public function test_generate_random_pseudo_bytes_must_succeed()
    {
        $p = new OpenSSLProxy();
        $length = mt_rand(1000, 9999);
        $result = $p->randomPseudoBytes($length);

        $this->assertInstanceOf(RandomPseudoBytesResult::class, $result);
        $this->assertEquals($length, strlen($result->value()));
        $this->assertIsBool($result->strongResult());
    }
}