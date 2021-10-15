<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

class RandomPseudoBytes extends String_
{
    public function strongResult(): bool
    {
        return $this->outParameters[1];
    }
}
