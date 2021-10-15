<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper;

use margusk\OpenSSL\Wrapper\Exception\BadMethodCallException;

class OpenSSL
{
    protected static ?Proxy $proxyInstance = null;

    protected function __construct()
    {
    }

    public static function __callStatic(string $method, array $arguments): mixed
    {
        $proxy = static::proxyInstance();

        if (method_exists($proxy, $method)) {
            return $proxy->{$method}(...$arguments);
        }

        throw new BadMethodCallException(sprintf('Unknown OpenSSL wrapper method "%s"', $method));
    }

    protected static function proxyInstance(): Proxy
    {
        if (null === static::$proxyInstance) {
            static::$proxyInstance = new Proxy();
        }

        return static::$proxyInstance;
    }
}
