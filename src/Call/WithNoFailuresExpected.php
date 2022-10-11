<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Call;

use margusk\OpenSSL\Wrapper\Call;

class WithNoFailuresExpected extends Call
{
    protected function init(): void
    {
        $this->expectedFailures = [];
    }
}