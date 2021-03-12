<?php

namespace Larva\Passport\Sms;

use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Bridge\UserRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\PasswordGrant;

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
     * @throws \Exception
     */
    public function boot()
    {
        app(AuthorizationServer::class)->enableGrantType($this->makeSmsRequestGrant(), Passport::tokensExpireIn());
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
     * @throws \Exception
     */
    protected function makeSmsRequestGrant()
    {
        $grant = new SmsRequestGrant(
            $this->app->make(UserRepository::class),
            $this->app->make(RefreshTokenRepository::class)
        );
        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
        return $grant;
    }
}