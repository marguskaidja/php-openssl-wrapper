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
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionExtension;
use ReflectionMethod;

class WrappedMethodsTest extends TestCase
{
    public function test_if_all_openssl_methods_are_wrapped()
    {
        // Collect functions from openssl extension
        $cmp1 = [];
        foreach ((new ReflectionExtension('openssl'))->getFunctions() as $name => $reflectionFunction) {
            $wrapperName = implode(
                '',
                array_map(function ($e) {
                    return ucfirst($e);
                }, explode('_', strtolower(substr($name, strlen('openssl_')))))
            );

            $wrapperName[0] = strtolower($wrapperName[0]);

            if (!in_array(
                $wrapperName,
                ['errorString', 'freeKey', 'pkeyFree', 'x509Free', 'getPrivatekey', 'getPublickey']
            )
            ) {
                $cmp1[] = $wrapperName;
            }
        }

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
}