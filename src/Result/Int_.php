<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

use margusk\OpenSSL\Wrapper\Result;

class Int_ extends Result
{
    public function value(): int
    {
        return $this->value;
    }
}