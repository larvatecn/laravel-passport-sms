<?php
/**
 * This is NOT a freeware, use is subject to license terms
 * @copyright Copyright (c) 2010-2099 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larva.com.cn/
 */
declare (strict_types=1);

namespace Larva\Passport\Sms;

use DateInterval;
use Exception;
use Illuminate\Http\Request;
use Laravel\Passport\Bridge\User;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

/**
 * Class SmsRequestGrant
 *
 * @author Tongle Xu <xutongle@gmail.com>
 */
class SmsGrant extends AbstractGrant
{
    /**
     * @param UserRepositoryInterface $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(UserRepositoryInterface $userRepository, RefreshTokenRepositoryInterface $refreshTokenRepository)
    {
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->refreshTokenTTL = new DateInterval('P1M');
    }

    /**
     * 获取标识
     * @return string
     */
    public function getIdentifier(): string
    {
        return 'sms';
    }

    /**
     * Respond to an incoming request.
     * @param ServerRequestInterface $request
     * @param ResponseTypeInterface $responseType
     * @param DateInterval $accessTokenTTL
     * @return ResponseTypeInterface
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType, DateInterval $accessTokenTTL): ResponseTypeInterface
    {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request));
        $user = $this->validateUser($request);

        // Finalize the requested scopes
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }

    /**
     * @param ServerRequestInterface $request
     * @return UserEntityInterface
     * @throws OAuthServerException
     */
    protected function validateUser(ServerRequestInterface $request): UserEntityInterface
    {
        $laravelRequest = new Request($request->getParsedBody());
        $user = $this->getUserEntityByRequest($laravelRequest);
        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidCredentials();
        }
        return $user;
    }

    /**
     * Retrieve user by request.
     *
     * @param Request $request
     * @return User|null
     */
    protected function getUserEntityByRequest(Request $request): ?User
    {
        $provider = config('auth.guards.api.provider');
        if (is_null($model = config('auth.providers.' . $provider . '.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }
        if (method_exists($model, 'findAndValidateForPassportSmsRequest')) {
            $user = (new $model)->findAndValidateForPassportSmsRequest($request);
            if (!$user) {
                return null;
            }
            return new User($user->getAuthIdentifier());
        } else {
            throw new RuntimeException('Unable to find findAndValidateForPassportSmsRequest method on user model.');
        }
    }
}