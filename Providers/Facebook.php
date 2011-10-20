<?php
/**
* HybridAuth
* 
* A Social-Sign-On PHP Library for authentication through identity providers like Facebook,
* Twitter, Google, Yahoo, LinkedIn, MySpace, Windows Live, Tumblr, Friendster, OpenID, PayPal,
* Vimeo, Foursquare, AOL, Gowalla, and others.
*
* Copyright (c) 2009-2011 (http://hybridauth.sourceforge.net) 
*/


/**
 * Hybrid_Providers_Facebook class, wrapper for Facebook Connect   
 */
class Hybrid_Providers_Facebook extends Hybrid_Provider_Model
{
	// permission to be requested from fb
	var $scope = "email, user_about_me, user_birthday, user_hometown, user_website, publish_stream, read_friendlists"; 

	/**
	* IDp wrappers initializer 
	*/
	function initialize() 
	{
		if ( ! $this->config["keys"]["id"] || ! $this->config["keys"]["secret"] )
		{
			throw new Exception( "Your application id and secret are required in order to connect to {$this->providerId}.", 4 );
		}

		require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/base_facebook.php";
		require_once Hybrid_Auth::$config["path_libraries"] . "Facebook/facebook.php";

		$this->api = new Facebook( ARRAY( 'appId' => $this->config["keys"]["id"], 'secret' => $this->config["keys"]["secret"] ) ); 
	}

   /**
	* begin login step
	* 
	* simply call Facebook::require_login(). 
	*/
	function loginBegin()
	{
		// if we have extra perm
		if( isset( $this->config["scope"] ) && ! empty( $this->config["scope"] ) )
		{
			$this->scope = $this->scope . ", ". $this->config["scope"];
		}

		// get the login url 
		$url = $this->api->getLoginUrl( array( 'scope' => $this->scope, 'redirect_uri' => $this->endpoint ) );

		// redirect to facebook
		Hybrid_Auth::redirect( $url ); 
	}

	/**
	* finish login step 
	*/
	function loginFinish()
	{ 
		// in case we get error_reason=user_denied&error=access_denied
		if ( isset( $_REQUEST['error'] ) && $_REQUEST['error'] == "access_denied" ){ 
			throw new Exception( "Authentification failed! The user denied your request.", 5 );
		}

		// try to get the UID of the connected user from fb 
		if ( ! $this->api->getUser() ){
			throw new Exception( "Authentification failed! {$this->providerId} returned an invalide user id.", 5 );
		}

		// set user as logged in
		$this->setUserConnected();

		// try to detect the access token for facebook
		foreach( $_SESSION as $k => $v ){ 
			if( strstr( $k, "fb_" ) && strstr( $k, "_access_token" ) ){
				$this->token( "access_token", $v );
			}
		}
	}

   /**
	* logout
	*/
	function logout()
	{ 
		$this->api->destroySession();

		parent::logout();
	}

   /**
	* load the user profile from the IDp api client
	*/
	function getUserProfile()
	{
		try{ 
			$data = $this->api->api('/me'); 
		}
		catch( Exception $e ){
			throw new Exception( "User profile request failed! {$this->providerId} returned an error while requesting the user profile.", 6 );
		} 

		// if the provider identifier is not recived, we assume the auth has failed
		if ( ! isset( $data["id"] ) )
		{ 
			throw new Exception( "User profile request failed! {$this->providerId} api returned an invalid response.", 6 );
		}

		# store the user profile.  
		$this->user->profile->identifier    = @ $data['id'];
		$this->user->profile->displayName   = @ $data['name'];
		$this->user->profile->firstName     = @ $data['first_name'];
		$this->user->profile->lastName     	= @ $data['last_name'];
		$this->user->profile->photoURL      = "https://graph.facebook.com/" . $this->user->profile->identifier . "/picture";
		$this->user->profile->profileURL 	= @ $data['link']; 
		$this->user->profile->webSiteURL 	= @ $data['website']; 
		$this->user->profile->gender     	= @ $data['gender'];
		$this->user->profile->description  	= @ $data['bio'];
		$this->user->profile->email      	= @ $data['email'];
		$this->user->profile->region      	= @ $data['hometown']["name"];

		if( isset( $data['birthday'] ) ) {
			list($birthday_month, $birthday_day, $birthday_year) = @ explode('/', $data['birthday'] );

			$this->user->profile->birthDay      = $birthday_day;
			$this->user->profile->birthMonth    = $birthday_month;
			$this->user->profile->birthYear     = $birthday_year;
		}

		return $this->user->profile;
 	}
}
