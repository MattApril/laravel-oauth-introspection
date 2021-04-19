<?php

namespace Ipunkt\Laravel\OAuthIntrospection\Http\Controllers;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Arr;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Laminas\Diactoros\Response as Psr7Response;

class IntrospectionController
{

    /**
     * @var Configuration
     */
    private $jwtConfig;

	/**
	 * @var \League\OAuth2\Server\ResourceServer
	 */
	private $resourceServer;

	/**
	 * @var \Laravel\Passport\Bridge\AccessTokenRepository
	 */
	private $accessTokenRepository;

	/**
	 * @var \Laravel\Passport\ClientRepository
	 */
	private $clientRepository;

    /**
     * @var \Illuminate\Contracts\Auth\UserProvider
     */
    private $userProvider;

    /**
     * @var string
     */
    protected $usernameProperty = 'email';

	/**
	 * constructing IntrospectionController
	 *
	 * @param \League\OAuth2\Server\ResourceServer $resourceServer
	 * @param \Laravel\Passport\Bridge\AccessTokenRepository $accessTokenRepository
	 * @param \Laravel\Passport\ClientRepository
     * @param \Illuminate\Contracts\Auth\UserProvider $userProvider
	 */
	public function __construct(
		ResourceServer $resourceServer,
		AccessTokenRepository $accessTokenRepository,
		ClientRepository $clientRepository,
        UserProvider $userProvider
	)
	{
		$this->resourceServer = $resourceServer;
		$this->accessTokenRepository = $accessTokenRepository;
		$this->clientRepository = $clientRepository;
		$this->userProvider = $userProvider;

		$signer = new Sha256();
		$publicKeyPath = Passport::keyPath('oauth-public.key');

		$key = InMemory::file($publicKeyPath);
		$jwtConfig = Configuration::forSymmetricSigner($signer, $key);
		$jwtConfig->setValidationConstraints(
			new ValidAt(new SystemClock(new \DateTimeZone(\date_default_timezone_get()))),
			new SignedWith(new Sha256(), $key)
		);

		$this->jwtConfig = $jwtConfig;
	}

	/**
	 * Authorize a client to access the user's account.
	 *
	 * @param  ServerRequestInterface $request
	 *
	 * @return JsonResponse|ResponseInterface
	 */
	public function introspectToken(ServerRequestInterface $request)
	{
		try {
			$this->resourceServer->validateAuthenticatedRequest($request);
        } catch (OAuthServerException $oAuthServerException) {
            return $oAuthServerException->generateHttpResponse(new Psr7Response);
        }

        if (Arr::get($request->getParsedBody(), 'token_type_hint', 'access_token') !== 'access_token') {
            //  unsupported introspection
            return $this->notActiveResponse();
        }

        $accessToken = Arr::get($request->getParsedBody(), 'token');
        if ($accessToken === null) {
            return $this->notActiveResponse();
        }

        $token = $this->jwtConfig->parser()->parse($accessToken);
        if (!$this->verifyToken($token)) {
            return $this->notActiveResponse();
        }

        $claims = $token->claims();

        # get user by token subject ID, from the UserProvider
        $user = $this->userProvider->retrieveById($claims->get('sub'));
        if( is_null($user) ) {
            return $this->notActiveResponse();
        }

        return $this->jsonResponse([
            'active' => true,
            'scope' => trim(implode(' ', (array)$claims->get('scopes', []))),
            'client_id' => intval($claims->get('aud')),
            'username' => $user->{$this->usernameProperty} ?? null,
            'token_type' => 'access_token',
            'exp' => $claims->get('exp')->getTimestamp(),
            'iat' => $claims->get('iat')->getTimestamp(),
            'nbf' => $claims->get('nbf')->getTimestamp(),
            'sub' => intval($claims->get('sub')),
            'aud' => intval($claims->get('aud')),
            'jti' => $claims->get('jti'),
        ]);
	}

	/**
	 * returns inactive token message
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	private function notActiveResponse() : JsonResponse
	{
		return $this->jsonResponse(['active' => false]);
	}

	/**
	 * @param array|mixed $data
	 * @param int $status
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	private function jsonResponse($data, $status = 200) : JsonResponse
	{
		return new JsonResponse($data, $status);
	}

	/**
	 * @param Token $token
	 * @return bool
	 */
	private function verifyToken(Token $token) : bool
	{
		try {

			if (!$this->jwtConfig->validator()->validate($token, ...$this->jwtConfig->validationConstraints())) {
				return false;
			}

			//  is token revoked?
			if ($this->accessTokenRepository->isAccessTokenRevoked($token->claims()->get('jti'))) {
				return false;
			}

			if ($this->clientRepository->revoked($token->claims()->get('aud'))) {
				return false;
			}

			return true;

		} catch (\Exception $exception) {
		}

		return false;
	}
}