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
 * Hybrid_Providers_Foursquare class, wrapper for Foursquare auth/api 
 */
class Hybrid_Providers_Foursquare extends Hybrid_Provider_Model
{ 
   /**
	* IDp wrappers initializer 
	*/
	function initialize() 
	{
		if ( ! $this->config["keys"]["key"] || ! $this->config["keys"]["secret"] )
		{
			throw new Exception( "Your application key and secret are required in order to connect to {$this->providerId}.", 4 );
		} 

		require_once Hybrid_Auth::$config["path_libraries"] . "Foursquare/FoursquareAPI.php"; 

		$this->api = new FoursquareAPI( $this->config["keys"]["key"], $this->config["keys"]["secret"] );

		// If we have an access token, set it
		if ( $this->token( "access_token" ) )
		{
			$this->api->SetAccessToken( $this->token( "access_token" ) );
		}
	}

   /**
	* begin login step 
	*/
	function loginBegin()
	{ 
		# redirect user to Foursquare authorisation web page
		Hybrid_Auth::redirect( $this->api->AuthenticationLink( urlencode( $this->endpoint ) ) ); 
	}

   /**
	* finish login step
	* 
	* fetch returned parameters by The IDp client
	*/
	function loginFinish()
	{
		$code = @ $_REQUEST['code'];
		
		$access_token = $this->api->GetToken( $code, urlencode( $this->endpoint ) );
 
		if ( ! $access_token )
		{
			throw new Exception( "Authentification failed! {$this->providerId} returned an invalid Access Token.", 5 );
		}

		$this->token( "access_token", $access_token ); 

		$this->setUserConnected();
	}

   /**
	* load the user profile from the IDp api client
	*/
	function getUserProfile()
	{
		try{ 
			$response = $this->api->GetPrivate( "users/self", array() );
			$data     = json_decode( $response );
		}
		catch( Exception $e ){
			throw new Exception( "AUser profile request failed! {$this->providerId} returned an error while requesting the user profile.", 6 );
		}

		if ( ! is_object( $data ) )
		{
			throw new Exception( "User profile request failed! {$this->providerId} api returned an invalide response.", 6 );
		}
 
		$this->user->profile->identifier    = @ $data->response->user->id;
		$this->user->profile->firstName  	= @ $data->response->user->firstName;
		$this->user->profile->lastName  	= @ $data->response->user->lastName;
		$this->user->profile->displayName  	= trim( $this->user->profile->firstName . " " . $this->user->profile->lastName );
		$this->user->profile->photoURL  	= @ $data->response->user->photo;
		$this->user->profile->profileURL    = @ "https://www.foursquare.com/user/" . $data->response->user->id;
		$this->user->profile->gender        = @ $data->response->user->gender;
		$this->user->profile->city          = @ $data->response->user->homeCity;
		$this->user->profile->email         = @ $data->response->user->contact->email;

		return $this->user->profile;
	}
}
