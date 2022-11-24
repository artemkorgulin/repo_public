<?php

namespace Rusklimat\PersonalBundle\Repository;

use Rusklimat\BitrixOrm\Repository\HlbReferenceRepository;
use Bitrix\Main\ArgumentException;
use Bitrix\Main\ObjectPropertyException;
use Bitrix\Main\SystemException;
use Doctrine\Common\Collections\ArrayCollection;

/**
 * Class JwtTokenRepository
 * @package Rusklimat\PersonalBundle\Repository
 */
class JwtTokenRepository extends HlbReferenceRepository
{
    /**
     * @param int $userId
     *
     * @return ArrayCollection
     * @throws ArgumentException
     * @throws ObjectPropertyException
     * @throws SystemException
     */
    public function findByUserId(int $userId): ArrayCollection
    {
        return $this->findBy(['UF_USER_ID' => $userId]);
    }

    /**
     * @param string $accessToken
     *
     * @return ArrayCollection
     * @throws ArgumentException
     * @throws ObjectPropertyException
     * @throws SystemException
     */
    public function findByAccessToken(string $accessToken): ArrayCollection
    {
        return $this->findBy(['UF_ACCESS_TOKEN' => $accessToken]);
    }

    /**
     * @param string $refreshToken
     *
     * @return ArrayCollection
     * @throws ArgumentException
     * @throws ObjectPropertyException
     * @throws SystemException
     */
    public function findByRefreshToken(string $refreshToken): ArrayCollection
    {
        return $this->findBy(['UF_REFRESH_TOKEN' => $refreshToken]);
    }
}
