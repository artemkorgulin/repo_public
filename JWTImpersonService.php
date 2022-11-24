<?php

namespace App\Services;

use App\Models\User;
use AnalyticPlatform\LaravelHelpers\Helpers\ExceptionHandlerHelper;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Application;
use Tymon\JWTAuth\JWTGuard;

/**
 * JWT Impersonation service
 *
 * @todo: add TTL support
 */
class JWTImpersonService
{

    /** @var string JWT token */
    private string $token;


    public function __construct(
        private Application $app
    ) {
    }


    /**
     * Login user (impersonator) as another user (subject)
     *
     * @param  User  $impersonator
     * @param  User  $subject
     * @param  string|null  $subjectGuardName
     *
     * @return bool
     */
    public function take(Authenticatable $impersonator, User $subject, ?string $subjectGuardName = null): bool
    {
        try {
            $impersonatorGuardName = $this->getAdminGuardName();

            //important: logging in and out as user fire events.
            //if we want to exclude this behaviour, we need to write silenced login and logout methods
            if ($impersonatorGuardName === $subjectGuardName) {
                $this->app['auth']->guard($impersonatorGuardName)->logout();
            }
            $this->token = $this->app['auth']->guard($subjectGuardName)->login($subject);

            session([
                $this->getImpersonatorIdSessionKey()    => $impersonator->getAuthIdentifier(),
                $this->getImpersonatorGuardSessionKey() => $impersonatorGuardName,
                $this->getSubjectIdSessionKey()         => $subject->id,
                $this->getSubjectGuardSessionKey()      => $subjectGuardName,
                $this->getSubjectTokenSessionKey()      => $this->token,
            ]);
        } catch (\Exception $exception) {
            report($exception);
            ExceptionHandlerHelper::logFail($exception);
            return false;
        }
        return $this->token;
    }


    /**
     * Log out from user that's being impersonated
     *
     * @return bool
     */
    public function leave(): bool
    {
        $impersonator          = $this->getImpersonator();
        $subjectGuardName      = $this->getSubjectGuardName();
        $impersonatorGuardName = $this->getImpersonatorGuardName();


        //log out impersonator's subject
        /** @var JWTGuard $guard */
        $this->app['auth']->guard($subjectGuardName)->setToken($this->getToken())->logout();

        //if impersonator's using same guard as his subject then log in him back
        if ($impersonatorGuardName === $subjectGuardName) {
            $this->app['auth']->guard($this->getImpersonatorGuardName())->login($impersonator);
        }

        $this->clear();

        return auth()->check();
    }


    /**
     * Remove all impersonating marks from session
     *
     * @return void
     */
    public function clear(): void
    {
        session()->forget([
            $this->getImpersonatorIdSessionKey(),
            $this->getImpersonatorGuardSessionKey(),
            $this->getSubjectIdSessionKey(),
            $this->getSubjectGuardSessionKey(),
            $this->getSubjectTokenSessionKey()
        ]);
    }


    /**
     * Get user by id
     *
     * @param  int  $id
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function findUserById(int $id): Authenticatable
    {
        return User::findOrFail($id);
    }


    /**
     * Return true if current user is impersonating someone
     *
     * @return bool
     */
    public function isImpersonating(): bool
    {
        return session()->has($this->getImpersonatorIdSessionKey());
    }


    /**
     * Get id of impersonator
     *
     * @return int
     */
    public function getImpersonatorId(): int
    {
        return session($this->getImpersonatorIdSessionKey());
    }


    /**
     * Get guard name of impersonator
     *
     * @return string
     */
    public function getImpersonatorGuardName(): string
    {
        return session($this->getImpersonatorGuardSessionKey());
    }


    /**
     * Get impersonator model
     *
     * @return Authenticatable|null
     */
    public function getImpersonator(): ?Authenticatable
    {
        $id = $this->getImpersonatorId();

        return is_null($id) ? null : $this->findUserById($id);
    }


    /**
     * Get id of subject that's being impersonated
     *
     * @return string
     */
    public function getSubjectId(): ?string
    {
        return session($this->getSubjectIdSessionKey());
    }


    /**
     * Get guard name of subject that's being impersonated
     *
     * @return string
     */
    public function getSubjectGuardName(): string
    {
        return session($this->getSubjectGuardSessionKey());
    }


    /**
     * Get default guard name
     *
     * @return string
     */
    public function getDefaultGuardName(): string
    {
        return 'admin';
    }


    /**
     * Get guard name for admin
     *
     * @return string|null
     */
    public function getAdminGuardName(): ?string
    {
        $guardName = config('nova.guard', $this->getDefaultGuardName());
        if ($this->app['auth']->guard($guardName)->check()) {
            return $guardName;
        }

        return null;
    }


    /**
     * Get JWT token
     * @return string|null
     */
    public function getToken(): ?string
    {
        return $this->token ?? session($this->getSubjectTokenSessionKey());
    }


    /**
     * The session key used to store the original user id.
     *
     * @return string
     */
    private function getImpersonatorIdSessionKey(): string
    {
        return 'impersonator_id';
    }


    /**
     * The session key used to store the original user guard.
     *
     * @return string
     */
    private function getImpersonatorGuardSessionKey(): string
    {
        return 'impersonator_guard';
    }


    /**
     * Get session key used to store name of guard of subject
     * that's being impersonated
     *
     * @return string
     */
    private function getSubjectGuardSessionKey(): string
    {
        return 'impersonator_subject_guard';
    }


    /**
     * Get session key used to store token of subject
     * that's being impersonated
     *
     * @return string
     */
    private function getSubjectTokenSessionKey(): string
    {
        return 'impersonator_subject_token';
    }


    /**
     * Get session key used to store id of subject
     * that's being impersonated
     *
     * @return string
     */
    private function getSubjectIdSessionKey(): string
    {
        return 'impersonator_subject_id';
    }
}
