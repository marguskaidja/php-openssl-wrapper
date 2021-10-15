<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

use margusk\OpenSSL\Wrapper\Result;

class String_ extends Result
{
    public function value(): string
    {
        return $this->value;
    }
}
