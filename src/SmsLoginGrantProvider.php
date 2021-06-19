<?php
/**
 * This is NOT a freeware, use is subject to license terms
 * @copyright Copyright (c) 2010-2099 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larva.com.cn/
 */
declare (strict_types=1);

namespace Larva\Passport\Sms;

use Exception;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Bridge\UserRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use League\OAuth2\Server\AuthorizationServer;

/**
 * Class SmsLoginGrantProvider
 *
 * @author Tongle Xu <xutongle@gmail.com>
 */
class SmsLoginGrantProvider extends PassportServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     * @throws Exception
     */
    public function boot()
    {
        $this->app->make(AuthorizationServer::class)->enableGrantType($this->makeSmsRequestGrant(), Passport::tokensExpireIn());
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
    }

    /**
     * Create and configure a Password grant instance.
     *
     * @return SmsRequestGrant
     * @throws Exception
     */
    protected function makeSmsRequestGrant(): SmsRequestGrant
    {
        $grant = new SmsRequestGrant(
            $this->app->make(UserRepository::class),
            $this->app->make(RefreshTokenRepository::class)
        );
        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
        return $grant;
    }
}