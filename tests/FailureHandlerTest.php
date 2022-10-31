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

use margusk\OpenSSL\Wrapper\Errors;
use margusk\OpenSSL\Wrapper\Exception\InvalidArgumentException;
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\Proxy\Options as OpenSSLProxyOptions;
use margusk\Warbsorber\Warnings;
use PHPUnit\Framework\TestCase;
use Throwable;

class FailureHandlerTest extends TestCase
{
    public function test_handler_matches_all_failed_functions()
    {
        $testMessage = "exception test message";

        $o = (new OpenSSLProxyOptions())->registerFailureHandler(
            'regex:.+',
            function ($exception) use ($testMessage): Throwable {
                return new CustomException($testMessage);
            }
        );

        $exception = $o->invokeFailureHandler(
            new OpenSSLCallFailedException(
                'dummy_function',
                new Errors(new Warnings([]), []),
                null
            )
        );

        $this->assertInstanceOf(CustomException::class, $exception);
        $this->assertEquals($testMessage, $exception->getMessage());
    }

    public function test_registering_multiple_handlers_must_work()
    {
        $testMessageSign = 'openssl_sign_message';
        $testMessageDummy = 'dummy_function_message';

        $o = (new OpenSSLProxyOptions())->registerFailureHandlers([
            'openssl_sign' => function ($exception) use ($testMessageSign): Throwable {
                return new CustomException($testMessageSign);
            },
            'regex:dummy_function.+' => function ($exception) use ($testMessageDummy): Throwable {
                return new CustomException($testMessageDummy);
            }
        ]);

        // Test "dummy_function" handler
        $exception = $o->invokeFailureHandler(
            new OpenSSLCallFailedException(
                'dummy_function2',
                new Errors(new Warnings([]), []),
                null
            )
        );

        $this->assertInstanceOf(CustomException::class, $exception);
        $this->assertEquals($testMessageDummy, $exception->getMessage());

        // Test "openssl_sign" handler
        $exception = $o->invokeFailureHandler(
            new OpenSSLCallFailedException(
                'openssl_sign',
                new Errors(new Warnings([]), []),
                null
            )
        );

        $this->assertInstanceOf(CustomException::class, $exception);
        $this->assertEquals($testMessageSign, $exception->getMessage());

        // Test default handler
        $defaultException = new OpenSSLCallFailedException(
            'some_other_function',
            new Errors(new Warnings([]), []),
            null
        );
        $exception = $o->invokeFailureHandler($defaultException);

        $this->assertEquals($exception, $defaultException);
    }

    public function test_handler_doesnt_match_function_which_isnt_registered()
    {
        $o = (new OpenSSLProxyOptions())->registerFailureHandler(
            'openssl_pkey_new',
            function ($exception): Throwable {
                return new CustomException('pkey call failed');
            }
        );

        $defaultException = new OpenSSLCallFailedException(
            'dummy_function',
                new Errors(new Warnings([]), []),
            null
        );

        $exception = $o->invokeFailureHandler($defaultException);

        $this->assertEquals($exception, $defaultException);
    }

    public function test_registering_failure_handler_with_invalid_regex_must_fail()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid REGEX pattern');

        (new OpenSSLProxyOptions())->registerFailureHandler(
            'regex:this[is_invalid_re}gex',
            function (OpenSSLCallFailedException $exception): Throwable {
                return $exception;
            }
        );
    }
}
