<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class HomeController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware(['auth', '2fa']);
    }

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function index()
    {
        return view('home');
    }

    public function reauthenticate(Request $request)
    {
        //get the logged in user
        $user =Auth::user();

         // Initialise the 2FA class
        $google2fa = app('pragmarx.google2fa');

        // generate a new secret key for the user
        $user->google2fa_secret = $google2fa->generateSecretKey();

        // save the user
        $user->save();

        // generate the QR image
         $QR_Image = $google2fa->getQRCodeInline(
            config('app.name'),
            $user->email,
            $user->google2fa_secret
        );
         // Pass the QR barcode image to our view.
         return view('google2fa.register',[
                                            'QR_Image'=> $QR_Image,
                                            'secret' => $user-> $user->google2fa_secret,
                                            'reauthenticate'=> true
                                        ]);
    }
}
