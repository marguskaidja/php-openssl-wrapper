<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

use margusk\OpenSSL\Wrapper\Parameter\Certificate as CertParam;
use margusk\OpenSSL\Wrapper\Result;

class Certificate extends Result
{
    public function value(): CertParam
    {
        return $this->value;
    }
}
