<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use App\User;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\RegistersUsers;

class RegisterController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Register Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users as well as their
    | validation and creation. By default this controller uses a trait to
    | provide this functionality without requiring any additional code.
    |
    */

    use RegistersUsers{
        register as registration;
    }

    /**
     * Where to redirect users after registration.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8', 'confirmed'],
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\User
     */
    protected function create(array $data)
    {
           return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
            'google2fa_secret' => $data['google2fa_secret'],
        ]);
    }

    public function register(Request $request)
    {
        //Xác thực yêu cầu
        $this->validator($request->all())->validate();

        // Khởi tạo lớp 2FA
        $google2fa = app('pragmarx.google2fa');

        // Lưu dữ liệu đăng ký trong một mảng
        $registrationData = $request->all();

        // Thêm Key vào dữ liệu đăng ký
        $registrationData['google2fa_secret'] = $google2fa->generateSecretKey();

        // Lưu dữ liệu đăng ký vào phiên người dùng cho yêu cầu tiếp theo
        $request->session()->flash('registration_data', $registrationData);

        // Tạo hình ảnh QR. Đây là hình ảnh người dùng sẽ quét bằng ứng dụng của họ
         // để thiết lập xác thực hai yếu tố
        $qrImage = $google2fa->getQRCodeInline(
            config('app.name'),
            $registrationData['email'],
            $registrationData['google2fa_secret']
        );

        // Hình ảnh mã vạch QR
        return view('google2fa.register', ['qrImage' => $qrImage, 'secret' => $registrationData['google2fa_secret']]);
    }

    public function completeRegistration(Request $request)
    {
        // thêm dữ liệu phiên trở lại đầu vào yêu cầu
        $request->merge(session('registration_data'));

        // Gọi xác thực laravel mặc định
        return $this->registration($request);
    }
}
