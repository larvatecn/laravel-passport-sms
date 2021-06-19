<?php
/**
 * This is NOT a freeware, use is subject to license terms
 * @copyright Copyright (c) 2010-2099 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larva.com.cn/
 */
declare (strict_types=1);

namespace Larva\Passport\Sms;

use Exception;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Bridge\UserRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;

/**
 * Passport Sms Grant
 *
 * @author Tongle Xu <xutongle@gmail.com>
 */
class PassportSmsGrantProvider extends ServiceProvider
{

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->afterResolving(AuthorizationServer::class, function (AuthorizationServer $oauthServer) {
            $oauthServer->enableGrantType($this->makeSmsGrant(), Passport::tokensExpireIn());
        });
    }

    /**
     * Create and configure a Password grant instance.
     *
     * @return SmsGrant
     * @throws Exception
     */
    protected function makeSmsGrant(): SmsGrant
    {
        $grant = new SmsGrant(
            $this->app->make(UserRepository::class),
            $this->app->make(RefreshTokenRepository::class)
        );
        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
        return $grant;
    }
}