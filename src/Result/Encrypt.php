<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

class Encrypt extends String_
{
    public function tag(): string
    {
        return $this->outParameters[5];
    }
}
