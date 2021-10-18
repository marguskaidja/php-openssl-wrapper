<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Tests;

use margusk\OpenSSL\Wrapper\Util;
use PHPUnit\Framework\TestCase;

class UtilTest extends TestCase
{
    public function test_php_emitted_warnings_must_be_silently_catched()
    {
        $phpTestWarning = [
            [
                'severity' => E_USER_WARNING,
                'message'  => 'This is test message1',
            ],
            [
                'severity' => E_USER_ERROR,
                'message'  => 'This is test message2',
            ],
            [
                'severity' => E_USER_WARNING,
                'message'  => 'This is test message3',
            ],
        ];

        $phpErrors = Util::catchPHPErrors(function () use ($phpTestWarning) {
            foreach ($phpTestWarning as $e) {
                trigger_error($e['message'], $e['severity']);
            }
        });

        foreach ($phpErrors as $n => $e) {
            unset($phpErrors[$n]['filename'], $phpErrors[$n]['lineno']);
        }

        $this->assertEqualsCanonicalizing($phpTestWarning, $phpErrors);
    }
}