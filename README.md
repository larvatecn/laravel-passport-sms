# SMS Grant for Laravel Passport

This package is useful to combine your Oauth2 Server with SMS Login.

## Installation

This package can be installed through Composer.

```
composer require larva/laravel-passport-sms
```

In Laravel 5.5 the service provider will automatically get registered. In older versions of the framework just add the service provider in config/app.php file:


```php
// config/app.php
'providers' => [
    ...
    "Larva\Passport\Sms\SmsLoginGrantProvider::class,
    ...
];
```
## How to use

* Make a POST request to https://your-site.com/oauth/token, just like you would a Password or Refresh grant.
* The POST body should contain grant_type = sms.
* The request will get routed to your User::findAndValidateForPassportSms() function, where you will determine if access should be granted or not.
* An access_token and refresh_token will be returned if successful.

## Request

```php
$response = $http->post('http://your-app.com/oauth/token', [
    'form_params' => [
        'grant_type' => 'sms',
        'client_id' => 'client-id',
        'client_secret' => 'client-secret',
        'phone' => '13800138000', 
        'verifyCode' => 'SMS verifyCode',
    ],
]);

## Example

Here is what a `User::findAndValidateForPassportSms()` method might look like...

```php
/**
 * Verify and retrieve user by custom token request.
 *
 * @param \Illuminate\Http\Request $request
 *
 * @return \Illuminate\Database\Eloquent\Model|null
 * @throws \League\OAuth2\Server\Exception\OAuthServerException
 */
public function findAndValidateForPassportSms(Request $request)
{
    try {
                Validator::make($request->all(), [
                    'phone' => [
                        'required',
                        'min:11',
                        'max:11',
                        'regex:/^1[34578]{1}[\d]{9}$|^166[\d]{8}$|^19[89]{1}[\d]{8}$/',
                    ],
                    'verifyCode' => [
                        'required',
                        'max:6',
                        function ($attribute, $value, $fail) use ($request) {
                            if (!SmsVerifyCodeService::make($request->phone)->validate($value, false)) {
                                return $fail($attribute . ' is invalid.');
                            }
                        },
                    ]
                ])->validate();
                return static::phone($request->phone)->first();
            } catch (\Exception $e) {
                throw OAuthServerException::accessDenied($e->getMessage());
            }
}
```

In this example, the app is able to authenticate a user based on an `phone`  and ``verifyCode property from a submitted JSON payload.  It will return `null` or a user object.  It also might throw exceptions explaining why the token is invalid.  The `byPassportSmsRequest` catches any of those exceptions and converts them to appropriate OAuth exception type.  If an `phone` is not present on the request payload, then we return `null` which returns an **invalid_credentials** error response:

```json
{
  "error": "invalid_credentials",
  "message": "The user credentials were incorrect."
}
```

## Credits:

* https://github.com/mikemclin/passport-custom-request-grant
