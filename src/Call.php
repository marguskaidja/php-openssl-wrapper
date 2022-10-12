<?php

/**
 * This file is part of the openssl-wrapper package.
 *
 * @author  Margus Kaidja <margusk@gmail.com>
 * @link    https://github.com/marguskaidja/php-openssl-wrapper
 * @license http://www.opensource.org/licenses/mit-license.php MIT (see the LICENSE file)
 */

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper;

use Closure;
use margusk\GetSet\Attributes\Set;
use margusk\GetSet\Attributes\Immutable;
use margusk\GetSet\GetSetTrait;
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\Parameter\AsymmetricKey;
use margusk\OpenSSL\Wrapper\Parameter\Certificate;
use margusk\OpenSSL\Wrapper\Parameter as ComplexParam;
use margusk\OpenSSL\Wrapper\Parameter\CSR;
use margusk\OpenSSL\Wrapper\Result\Array_ as ArrayResult;
use margusk\OpenSSL\Wrapper\Result\AsymmetricKey as KeyResult;
use margusk\OpenSSL\Wrapper\Result\Bool_ as BoolResult;
use margusk\OpenSSL\Wrapper\Result\Certificate as CertResult;
use margusk\OpenSSL\Wrapper\Result\Encrypt as EncryptResult;
use margusk\OpenSSL\Wrapper\Result\Int_ as IntResult;
use margusk\OpenSSL\Wrapper\Result\RandomPseudoBytes as RandomPseudoBytesResult;
use margusk\OpenSSL\Wrapper\Result\Seal as SealResult;
use margusk\OpenSSL\Wrapper\Result\String_ as StringResult;
use margusk\OpenSSL\Wrapper\Result\CSRNew as CSRNewResult;

/**
 * @method self with(array|string $properties, mixed $value = null)
 * @method self withParameters(array $value)
 * @method self withExpectedFailures(array $value)
 * @method self withReturnNthParameter(int $value)
 */
#[Set,Immutable]
class Call
{
    use GetSetTrait;

    protected array $parameters = [];

    protected array $expectedFailures = [false];

    protected ?int $returnNthParameter = null;

    public function __construct(
        protected Proxy $proxy,
        protected string $funcNameSuffix
    ) {
        $this->init();
    }

    protected function init(): void
    {
        // placeholder for extended classes
    }

    public function getArrayResult(): ArrayResult
    {
        return $this->execute(ArrayResult::class);
    }

    protected function convertComplexParam(array $params, int $lvl = 0): array
    {
        foreach ($params as $n => $p) {
            if ($p instanceof ComplexParam) {
                $params[$n] = $p->internal();
            } elseif (0 === $lvl && is_array($p)) {
                $params[$n] = $this->convertComplexParam($params[$n], $lvl + 1);
            }
        }

        return $params;
    }

    protected function execute(string $resultClass, Closure $resultValueCreator = null): Result
    {
        $funcName = 'openssl_'.$this->funcNameSuffix;
        $funcNamePrefix = $funcName.'():';
        $lenPrefix = strlen($funcNamePrefix);

        // Convert AsymmetricKey, Certificate and CSR into internal representation
        $outParameters = $this->convertComplexParam($this->parameters);

        $this->flushOpenSSLErrors();

        // Execute call and submit $params by reference, in case the internal method
        // wants to change one of them (e.g. openssl_sign)
        $nativeResult = null;

        $phpErrors = Util::catchPHPErrors(
            function () use (&$nativeResult, $funcName, &$outParameters) {
                $nativeResult = $funcName(...$outParameters);
            }
        );

        // Remove function name prefix from messages
        foreach ($phpErrors as $n => $error) {
            if (strcasecmp(substr($error['message'], 0, $lenPrefix), $funcNamePrefix) == 0) {
                $phpErrors[$n]['message'] = trim(substr($error['message'], $lenPrefix));
            }
        }

        $errors = new Errors($phpErrors, $this->collectOpenSSLErrors());
        $callFailed = false;

        if (count($this->expectedFailures)) {
            $callFailed = in_array($nativeResult, $this->expectedFailures, true);
        }

        if ($callFailed) {
            throw $this->proxy->options()->invokeFailureHandler(
                new OpenSSLCallFailedException($funcName, $errors, $nativeResult)
            );
        }

        if (null !== $this->returnNthParameter) {
            $nativeResult = $outParameters[$this->returnNthParameter];
        }

        if ($resultValueCreator) {
            $nativeResult = $resultValueCreator($nativeResult);
        }

        return new $resultClass($funcName, $this->parameters, $outParameters, $nativeResult, $errors);
    }

    protected function flushOpenSSLErrors(): static
    {
        /** @noinspection PhpStatementHasEmptyBodyInspection */
        while (false !== openssl_error_string()) {
        }

        return $this;
    }

    protected function collectOpenSSLErrors(): array
    {
        $result = [];
        while (false !== ($err = openssl_error_string())) {
            $result[] = $err;
        }
        return $result;
    }

    public function getIntResult(): IntResult
    {
        return $this->execute(IntResult::class);
    }

    public function getStringResult(): StringResult
    {
        return $this->execute(StringResult::class);
    }

    public function getBoolResult(): BoolResult
    {
        return $this->execute(BoolResult::class);
    }

    public function getKeyResult(): KeyResult
    {
        return $this->execute(
            KeyResult::class,
            function (mixed $nativeResult) {
                return new AsymmetricKey($this->proxy, $nativeResult);
            }
        );
    }

    public function getCSRNewResult(): CSRNewResult
    {
        return $this->execute(
            CSRNewResult::class,
            function (mixed $nativeResult) {
                return new CSR($this->proxy, $nativeResult);
            }
        );
    }

    public function getCertResult(): CertResult
    {
        return $this->execute(
            CertResult::class,
            function (mixed $nativeResult) {
                return new Certificate($this->proxy, $nativeResult);
            }
        );
    }

    public function getSealResult(): SealResult
    {
        return $this->execute(SealResult::class);
    }

    public function getEncryptResult(): EncryptResult
    {
        return $this->execute(EncryptResult::class);
    }

    public function getRandomPseudoBytesResult(): RandomPseudoBytesResult
    {
        return $this->execute(RandomPseudoBytesResult::class);
    }
}
