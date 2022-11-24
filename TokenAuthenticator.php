<?php
declare(strict_types=1);

/**
 *
 */

namespace Elt\AuthBundle\Security;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Exception;

/**
 * Class TokenAuthenticator
 */
class TokenAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @param Request $request
     *
     * @return bool
     */
    public function supports(Request $request)
    {
        return $request->headers->has('Authorization');
    }

    /**
     * @param Request $request
     *
     * @return array|mixed|string|null
     */
    public function getCredentials(Request $request)
    {
        return $request->headers->get('Authorization');
    }

    /**
     * @param mixed                 $credentials - Bearer Токен
     * @param UserProviderInterface $userProvider
     *
     * @return array|object|UserInterface|null
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if (null === $credentials) {
            return null;
        }

        try {
            return $userProvider->loadUserByUsername($credentials);
        } catch (Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }
    }

    /**
     * @param mixed         $credentials
     * @param UserInterface $user
     *
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    /**
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey
     *
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $token->setAttribute('token', $this->getCredentials($request));
        return null;
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return JsonResponse|Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    /**
     * Called when authentication is needed, but it's not sent
     *
     * @param Request                      $request
     * @param AuthenticationException|null $authException
     *
     * @return JsonResponse
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $data = [
            'message' => 'Authentication Required',
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    /**
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }
}
