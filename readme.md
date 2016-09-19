##JWTAuth 


####Config/app.php

	Tymon\JWTAuth\Providers\JWTAuthServiceProvider::class,


	'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class,
	'JWTFactory' => Tymon\JWTAuth\Facades\JWTFactory::class,


####Conposer: 

To create config\jwt.php

	php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\JWTAuthServiceProvider"


	>>Result: Copied File [\vendor\tymon\jwt-auth\src\config\config.php] To [\config\jwt.php]


To create key JWT in `config/app.php`

	php artisan jwt:generate

####kernel.php

	'jwt.auth' => \Tymon\JWTAuth\Middleware\GetUserFromToken::class,
	'jwt.refresh' => \Tymon\JWTAuth\Middleware\RefreshToken::class,




#####app\Exceptions\Handler.php

    if ($e instanceof ModelNotFoundException) {

        $e = new NotFoundHttpException($e->getMessage(), $e);
        
    }

    if($e instanceof TokenExpiredException){

        return response()->json(['token_expired'], 401);
        
    }else if($e instanceof TokenInvalidException){
        
        return response()->json(['token_invalid'], 401);

    }else if($e instanceof TokenBacklistedException){
        
        return response()->json(['token_backlisted'], 500);

    }

    return parent::render($request, $e);



####routes.php

	$api->version('v1', ['middleware' => 'jwt.auth'], function($api){

		$api->get('users', 'App\Http\Controllers\Auth\AuthController@index');
		$api->get('users/{user_id}', 'App\Http\Controllers\Auth\AuthController@show');
		$api->get('token', 'App\Http\Controllers\Auth\AuthController@getToken');
	});


 
####app\Auth\AuthController.php

 Try catch API


use Illuminate\Http\Request;
use JWTAuth;

    public function authenticate(Request $request){
        $credentials = $request->only('email','password');

        $login = filter_var($request->input('email'), FILTER_VALIDATE_EMAIL) ? 'email' : 'phone';

        try {

            if($login == 'email'){
                $loginCredentials = [
                                'email' => $credentials['email'],
                                'password' => $credentials['password']
                                ];
            }else{
                $loginCredentials = [
                                'phone' => $credentials['email'],
                                'password' => $credentials['password']
                                ];
            }


            if(!$token = JWTAuth::attempt($loginCredentials)){
                return $this->response->errorUnauthorized();
            }

        } catch (JWTException $ex) {
            return $this->response->errorInternal();
        }

        return $this->response->array(compact('token'))->setStatusCode(200);
    }


    public function index(){

        try {

            return User::all();

        } catch (Exception $e) {
            return $e;
        }
        
    }

    public function show($user_id){

        try {
            $user = JWTAuth::parseToken()->toUser();

            if(!$user){
                return $this->response->errorNotFound("User not found");
            }
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $ex) {
            return $this->response->error('Something went wrong');
        }
        return $this->response->array(compact('user'))->setStatusCode(200);
        
    }


Note, commit __construct:

    // public function __construct()
    // {
    //     $this->middleware('guest', ['except' => 'getLogout']);
    // }


