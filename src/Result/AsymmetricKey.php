<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

use margusk\OpenSSL\Wrapper\Parameter\AsymmetricKey as AsymmetricKeyParam;
use margusk\OpenSSL\Wrapper\Result;

class AsymmetricKey extends Result
{
    public function value(): AsymmetricKeyParam
    {
        return $this->value;
    }
}
