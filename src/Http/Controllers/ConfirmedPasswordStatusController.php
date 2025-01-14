<?php

namespace Laravel\Fortify\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class ConfirmedPasswordStatusController extends Controller
{
    /**
     * Get the password confirmation status.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function show(Request $request)
    {
        $confirmedAt = $request->hasSession() ?
            $request->session()->get('auth.password_confirmed_at', 0)
            : 0;

        return response()->json([
            'confirmed' => (time() - $confirmedAt) < $request->input('seconds', config('auth.password_timeout', 900)),
        ]);
    }
}
