<?php

/**
 *
 * OAuthController
 *
 * oauth auth consumer
 *
 */
App::import('File', 'OAuthRequester', null, array('../Vendor/oauth-php/library/'), 'OAuthRequester.php');

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class OAuthAuthenticate extends BaseAuthenticate {

    public $settings = array(
        'debug'=> 0,
        'userModel' => 'User',
        'method' => 'POST',
        'usr_id' => 0,
        'key' => '',
        'secret' => '',
        'base_url' => '',
        'store_type' => 'Session',
        'path_request_token' => '/oauth/request_token',
        'path_auth' => '/oauth/authorize',
        'path_access' => '/oauth/access_token',
        'path_user_info' => '/oauthlogin/api/user/info',
        'curl_options' => array(
            // skip ssl strict checks eg. for self-signed certs
            CURLOPT_SSL_VERIFYPEER => 0,
            CURLOPT_SSL_VERIFYHOST => 0,
        )
    );
    public $options = array(
        'consumer_key' => '',
        'consumer_secret' => '',
        'server_uri' => '',
        'request_token_uri' => '',
        'authorize_uri' => '',
        'access_token_uri' => '',
        'name' => '',
    );

    protected function getController() {
        static $ref = null;
        if (is_null($ref)) {
            App::import('Controller', 'App');
            $appController = new AppController();
            $appController->constructClasses();
            $ref = $appController;
        }
        return $ref;
    }

    /**
     * Authenticates the identity contained in a request.  Will use `settings.fields`
     * to find POST data that is used to find a matching record in the `settings.userModel`.
     * Will return false if there is no post data, either username or password is missing,
     * of if the scope conditions have not been met.
     *
     * @param CakeRequest $request The request that contains login information.
     * @param CakeResponse $response Unused response object.
     * @return mixed.  False on login failure.  An array of User data on success.
     */
    public function authenticate(CakeRequest $_request, CakeResponse $_response) {


        $key = $this->settings['key']; // this is your consumer key
        $secret = $this->settings['secret']; // this is your secret key

        $base_url = $this->settings['base_url']; // this is the URL of the request
        $method = $this->settings['method']; // you can also use POST instead
        $path_request_token = $this->settings['path_request_token'];
        $path_auth = $this->settings['path_auth'];
        $path_access = $this->settings['path_access'];
        $name = $this->settings['name'];
        $usr_id = $this->settings['usr_id'];

        if (empty($key) || empty($secret) || empty($base_url)) {
            return false;
        }

        //  Init the OAuthStore
        $this->options = array(
            'consumer_key' => $key,
            'consumer_secret' => $secret,
            'server_uri' => $base_url,
            'request_token_uri' => $base_url . $path_request_token,
            'authorize_uri' => $base_url . $path_auth,
            'access_token_uri' => $base_url . $path_access,
            'name' => $name,
        );

        OAuthStore::instance($this->settings['store_type'], $this->options);

        
        $appController = $this->getController();

//      clear all session data
//
/*
        $appController->Session->delete("requestTokens");
        $appController->Session->delete("oauthToken");
        $appController->Session->delete("oauthUser");
//*/
        if ($appController->Session->check("oauthAccess")) {
            $user = $this->getUser();
            if($user) {
                return $this->getUser();
            }
            else{
                // clear out
                $this->logout(null);
            }
        }
        
        $requestTokens = null;
        if ($appController->Session->check("requestTokens")) {
            $requestTokens = $appController->Session->read("requestTokens");
        }
        if ($requestTokens) {

            if (isset($_GET['oauth_token'])) {
                $oauth_token = $_GET['oauth_token'];
            } else {

                $appController->Session->delete("oauthAccess");
                $appController->Session->delete("requestTokens");
                $this->log( __("Missing oauth_token.") );
                return false;
            }

            try {

                $consumer_key = $key;
                $token = $oauth_token;
                $curl_options = array();
                if(isset($this->settings['curl_options']) && is_array($this->settings['curl_options'])){
                    $curl_options += $this->settings['curl_options'];
                }

                OAuthRequester::requestAccessToken($consumer_key, $token, $usr_id, $method, $this->options, $curl_options);

                $appController->Session->write("oauthAccess", true);

                return $this->getUser();
            } catch (Exception $e) {
                //krumo($e->getMessage());
                $appController->Session->delete("oauthAccess");
                $appController->Session->delete("requestTokens");
                $this->log( $e );
            }

        } else {

            $appController->Session->delete("requestTokens");
            $appController->Session->delete("oauthAccess");

            $params = null;
            $response = false;
            try {

                $getAuthTokenParams = array(
                    'oauth_callback' => 'oob',
                );

                $curl_options = array();
                if(isset($this->settings['curl_options']) && is_array($this->settings['curl_options'])){
                    $curl_options += $this->settings['curl_options'];
                }

                // get a request token
                $tokenResultParams = OAuthRequester::requestRequestToken($key, 0, $getAuthTokenParams, 'POST', $this->options, $curl_options);
                $appController = $this->getController();

                $appController->Session->write("requestTokens", $tokenResultParams);

                //krumo($tokenResultParams);
                //  redirect to the opera authorization page, they will redirect back
                OAuthRequester::redirect($tokenResultParams['authorize_uri'], array('oauth_token' => $tokenResultParams['token']));
            } catch (OAuthException2 $e) {
                $this->log( $e );
            } catch (Exception $e) {
                $this->log( $e );
            }

            return false;
        }
    }

    public function logout($user) {

        $appController = $this->getController();

        $appController->Session->delete("oauthUser");
        $appController->Session->delete("oauthAccess");
        $appController->Session->delete("requestToken");
    }

    public function getUser() {

        OAuthStore::instance($this->settings['store_type'], $this->options);
        $appController = $this->getController();

        $base_url = $this->settings['base_url'];
        if($appController->Session->check("oauthUser"))
        {
            $user = $appController->Session->read("oauthUser");
            return $user;
        }

        try {
            $path_access = $this->settings['path_access'];

            $options = array();

            $curl_options = array();
            if(isset($this->settings['curl_options']) && is_array($this->settings['curl_options'])){
                $curl_options += $this->settings['curl_options'];
            }
            
            $request = new OAuthRequester($base_url . $this->settings['path_user_info'], 'POST', $options);
            $result = $request->doRequest(0, $curl_options);
            
            if ($result['code'] == 200) {

                $data = $result['body'];
                $user = Xml::toArray(simplexml_load_string($data));

                $appController->Session->write("oauthUser", $user);
                return (array) $user;
                

            } else {
                $this->log( __("An error occured while requesting resource data.") );
                return false;
            }
        } catch (Exception $e) {
            $this->log( $e );
        }

        $this->logout( null );
        return false;
    }

    private function log( $e ){

        if(isset($this->settings['debug']) && $this->settings['debug'])
        {
            debug(  $e->getMessage() . "\n\n[".
                    $e->getTraceAsString(). "]\n".
                    ' at line '.$e->getLine()
                 );
        }
        else
        {
            $ctrl = $this->getController();
            
            $msg = $e;
            if( method_exists($e, 'getMessage'))
            {
                $msg = $e->getMessage();
            }
            $ctrl->Session->setFlash(__("An error happened while trying to authenticate: ") . $msg);
        }
    }

}