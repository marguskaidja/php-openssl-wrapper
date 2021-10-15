<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper;

use margusk\OpenSSL\Wrapper\Parameter\Contract as ParameterContract;

abstract class Parameter implements ParameterContract
{
    public function __construct(
        protected Proxy $proxy,
        protected mixed $internal
    ) {
    }

    public function proxy(): Proxy
    {
        return $this->proxy;
    }
}