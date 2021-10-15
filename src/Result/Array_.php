<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

use margusk\OpenSSL\Wrapper\Result;

class Array_ extends Result
{
    public function value(): array
    {
        return $this->value;
    }
}
