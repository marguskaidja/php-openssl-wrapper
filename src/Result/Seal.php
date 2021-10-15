<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

class Seal extends String_
{
    public function encryptedKeys(): array
    {
        return $this->outParameters[2];
    }

    public function iv(): string
    {
        return $this->outParameters[5];
    }
}
