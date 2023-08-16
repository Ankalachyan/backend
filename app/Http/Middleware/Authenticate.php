<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Illuminate\Http\Request;

class Authenticate extends Middleware
{
    /**
     * Get the path the user should be redirected to when they are not authenticated.
     */
    protected function redirectTo($request)
    {
        return $request->expectsJson() ? null : route('login');
    }
    public function handle($request, Closure $next, ...$gurds)
    {
        if ($token = $request->cookie("token")) {
           $request->headers->set('Authorization',"Bearer" . $token);
        }
        $this->authenticate($request,$gurds);
        return $next($request);

    }
}
