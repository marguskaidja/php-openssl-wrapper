<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

use margusk\OpenSSL\Wrapper\Result;

class Bool_ extends Result
{
    public function value(): bool
    {
        return $this->value;
    }
}