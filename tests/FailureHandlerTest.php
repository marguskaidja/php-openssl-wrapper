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

use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\Proxy as OpenSSLProxy;
use PHPUnit\Framework\TestCase;
use Throwable;

class FailureHandlerTest extends TestCase
{
    public function test_handler_matches_all_failed_functions()
    {
        $testMessage = md5(uniqid((string)mt_rand()));

        $this->expectException(CustomException::class);
        $this->expectExceptionMessage($testMessage);

        $p = new OpenSSLProxy();
        $p->options()->onCallFailed('regex:.+', function ($exception) use ($testMessage): Throwable {
            return new CustomException($testMessage);
        });

        $p->cipherIvLength("non-existing-cipher");
    }

    public function test_handler_doesnt_match_function_which_isnt_registered()
    {
        $this->expectException(OpenSSLCallFailedException::class);

        $p = new OpenSSLProxy();
        $p->options()->onCallFailed('openssl_pkey_new', function ($exception): Throwable {
            return new CustomException('pkey call failed');
        });

        $p->cipherIvLength("non-existing-cipher");
    }
}
