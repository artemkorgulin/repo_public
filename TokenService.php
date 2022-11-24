<?php
declare(strict_types = 1);


namespace Rusklimat\PersonalBundle\Service;


use Rusklimat\BitrixOrmBundle\Registry\RepositoryRegistryInterface;
use Rusklimat\BitrixUserBundle\Entity\UserInterface;
use Rusklimat\BitrixUserBundle\Services\UserManagerInterface;
use Rusklimat\PersonalBundle\Model\JwtToken;
use Rusklimat\PersonalBundle\Repository\JwtTokenRepository;
use Bitrix\Main\ArgumentException;
use Bitrix\Main\ObjectPropertyException;
use Bitrix\Main\SystemException;
use Bitrix\Main\Type\DateTime;
use Exception;
use Firebase\JWT\JWT;


/**
 * Class TokenService
 * @package Rusklimat\PersonalBundle\Service
 */
class TokenService
{
    /**
     * Время жизни ключа авторизации в секундах
     */
    private const ACCESS_EXPIRE_SECONDS = 900;
    /**
     * Время жизни ключа восстановления в днях
     */
    private const REFRESH_EXPIRE_DAYS   = 30;
    /**
     * Ключ шифрования
     *
     * @var string
     */
    private static $SECRET_KEY;

    /**
     * @var JwtTokenRepository
     */
    protected $jwtTokenRepository;
    /**
     * @var UserManagerInterface
     */
    protected $userManager;

    public function __construct(
        RepositoryRegistryInterface $repositoryRegistry,
        UserManagerInterface $userManager
    )
    {
        self::$SECRET_KEY = getenv('BITRIX_CRYPTO_KEY');
        $this->jwtTokenRepository = $repositoryRegistry->get(JwtToken::class);
        $this->userManager = $userManager;
    }

    /**
     * @param UserInterface $user
     *
     * @return JwtToken
     * @throws Exception
     */
    public function makeUserToken(UserInterface $user): JwtToken
    {
        $accessToken  = $this->generateAccessToken($user);
        $refreshToken = $this->generateRefreshToken($user, $accessToken);

        $jwtToken = (new JwtToken())
            ->setUserId($user->getId())
            ->setAccessToken($accessToken)
            ->setAccessExpire($this->getAccessTokenExpire())
            ->setRefreshToken($refreshToken)
            ->setRefreshExpire($this->getRefreshTokenExpire())
            ->setLastUpdate(new DateTime());
        $this->deleteUserToken($user);
        $this->saveToken($jwtToken);

        return $jwtToken;
    }

    /**
     * @param string $token
     *
     * @throws Exception
     */
    public function updateUserToken(string $token): void
    {
        try {
            $jwtToken = $this->jwtTokenRepository->findByAccessToken($token)->getIterator()->current();
        } catch (ArgumentException | ObjectPropertyException | SystemException $e) {
            $jwtToken = null;
        }

        if ($jwtToken instanceof JwtToken) {
            $jwtToken
                ->setAccessExpire($this->getAccessTokenExpire())
                ->setRefreshExpire($this->getRefreshTokenExpire())
                ->setLastUpdate(new DateTime());
            $this->jwtTokenRepository->update($jwtToken);
        }
    }

    /**
     * @param UserInterface $user
     *
     * @throws ArgumentException
     * @throws ObjectPropertyException
     * @throws SystemException
     */
    public function deleteUserToken(UserInterface $user): void
    {
        $tokenCollection = $this->jwtTokenRepository->findByUserId($user->getId());
        foreach ($tokenCollection->getIterator() as $token) {
            $this->jwtTokenRepository->delete($token);
        }
    }

    /**
     * @param string $token
     *
     * @return UserInterface
     */
    public function getUserByToken(string $token): ?UserInterface
    {
        $userId = $this->getUserIdByToken($token);
        $user   = $userId ? $this->userManager->getById($userId) : null;

        return $user ?? null;
    }

    /**
     * @param string $token
     *
     * @return int
     */
    public function getUserIdByToken(string $token): ?int
    {
        $decodedToken = JWT::decode($token, base64_decode(self::$SECRET_KEY), ['HS256']);

        return $decodedToken->data->userId;
    }

    /**
     * @param string $token
     *
     * @return bool
     * @throws Exception
     */
    public function isNotExpireToken(string $token): bool
    {
        try {
            $jwtToken = $this->jwtTokenRepository->findByAccessToken($token)->getIterator()->current();
        } catch (ArgumentException | ObjectPropertyException | SystemException $e) {
            $jwtToken = null;
        }

        return ($jwtToken instanceof JwtToken && $jwtToken->getAccessExpire()->getTimestamp() > time()) ?: false;
    }

    /**
     * @param string $token
     *
     * @return bool
     * @throws Exception
     */
    public function isNotExpireRefreshToken(string $token): bool
    {
        try {
            $jwtToken = $this->jwtTokenRepository->findByRefreshToken($token)->getIterator()->current();
        } catch (ArgumentException | ObjectPropertyException | SystemException $e) {
            $jwtToken = null;
        }

        return ($jwtToken instanceof JwtToken && $jwtToken->getRefreshExpire()->getTimestamp() > time()) ?: false;
    }

    /**
     * @param UserInterface $user
     *
     * @return string
     * @throws Exception
     */
    private function generateAccessToken(UserInterface $user): string
    {
        return JWT::encode([
            'iat' => time(),
            'data' => [
                'userId' => $user->getId(),
                'guid'   => self::getGUID(),
            ],
        ], base64_decode(self::$SECRET_KEY));
    }

    /**
     * @param UserInterface $user
     * @param string        $accessToken
     *
     * @return string
     */
    private function generateRefreshToken(UserInterface $user, string $accessToken): string
    {
        return JWT::encode([
            'iat' => time(),
            'data' => [
                'userId' => $user->getId(),
                'token'  => $accessToken,
            ],
        ], base64_decode(self::$SECRET_KEY));
    }

    /**
     * @return DateTime
     */
    private function getAccessTokenExpire(): DateTime
    {
        return (new DateTime())->add('PT'.self::ACCESS_EXPIRE_SECONDS.'S');
    }

    /**
     * @return DateTime
     */
    private function getRefreshTokenExpire(): DateTime
    {
        return (new DateTime())->add('P'.self::REFRESH_EXPIRE_DAYS.'D');
    }

    /**
     * @param JwtToken $jwtToken
     *
     * @throws Exception
     */
    private function saveToken(JwtToken $jwtToken): void
    {
        $this->jwtTokenRepository->add($jwtToken);
    }

    /**
     * @return string
     * @throws Exception
     */
    private static function getGUID(): string
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            random_int(0, 0xffff), random_int(0, 0xffff),
            random_int(0, 0xffff),
            random_int(0, 0x0fff) | 0x4000,
            random_int(0, 0x3fff) | 0x8000,
            random_int(0, 0xffff), random_int(0, 0xffff), random_int(0, 0xffff)
        );
    }
}
