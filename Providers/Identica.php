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
* Hybrid_Providers_Identica
*/
class Hybrid_Providers_Identica extends Hybrid_Provider_Model
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

		require_once Hybrid_Auth::$config["path_libraries"] . "TwitterCompatible/OAuth.php";
		require_once Hybrid_Auth::$config["path_libraries"] . "TwitterCompatible/TwitterCompatibleClient.php";
		require_once Hybrid_Auth::$config["path_libraries"] . "TwitterCompatible/Identica.php";

		if( $this->token( "access_token" ) && $this->token( "access_token_secret" ) )
		{
			$this->api = new Identica_Client
							( 
								$this->config["keys"]["key"], $this->config["keys"]["secret"],
								$this->token( "access_token" ), $this->token( "access_token_secret" ) 
							);
		}
	}

   /**
	* begin login step 
	*/
	function loginBegin()
	{
 	    $this->api = new Identica_Client( $this->config["keys"]["key"], $this->config["keys"]["secret"] );

		try{ 
			$tokz = $this->api->getRequestToken( $this->endpoint ); 
		}
		catch( Exception $e ){
			throw new Exception( "Authentification failed! {$this->providerId} returned an error while requesting a request token.", 5 );
		} 
		
		if ( ! count( $tokz ) )
		{
			throw new Exception( "Authentification failed! Could not connect to {$this->providerId}.", 5 );
		}

		$this->token( "request_token"       , $tokz["oauth_token"] ); 
		$this->token( "request_token_secret", $tokz["oauth_token_secret"] ); 

		# redirect user to Tumblr 
		Hybrid_Auth::redirect( $this->api->getAuthorizeURL( $tokz ) );
	}

   /**
	* finish login step 
	*/ 
	function loginFinish()
	{ 
		$oauth_token    = @ $_REQUEST['oauth_token']; 
		$oauth_verifier = @ $_REQUEST['oauth_verifier']; 

		if ( ! $oauth_token || ! $oauth_verifier )
		{
			throw new Exception( "Authentification failed! {$this->providerId} returned an invalid OAuth Token and Verifier.", 5 );
		}

		try{ 
			$this->api = new Identica_Client( 
								$this->config["keys"]["key"], $this->config["keys"]["secret"], 
								$this->token( "request_token" ), $this->token( "request_token_secret" ) 
							);

			$tokz = $this->api->getAccessToken( $oauth_verifier );
		}
		catch( Exception $e ){
			throw new Exception( "Authentification failed! {$this->providerId} returned an error while requesting an access token.", 5 );
		} 

		if ( ! count( $tokz ) )
		{
			throw new Exception( "Authentification failed! {$this->providerId} returned an invalid access token.", 5 );
		}

		$this->token( "access_token"        , $tokz['oauth_token'] );
		$this->token( "access_token_secret" , $tokz['oauth_token_secret'] ); 

		// set user as logged in
		$this->setUserConnected();
	}

   /**
	* load the user profile from the IDp api client
	*/
	function getUserProfile()
	{
		try{ 
			$response = $this->api->get( 'account/verify_credentials' ); 
		}
		catch( Exception $e ){
			throw new Exception( "User profile request failed! {$this->providerId} returned an error while requesting the user profile.", 6 );
		}

		if ( ! $response )
		{
			throw new Exception( "User profile request failed! {$this->providerId} api returned an invalid response.", 6 );
		} 

		# store the user profile.  
		$this->user->profile->identifier    = @ $response->id;
		$this->user->profile->displayName  	= @ $response->screen_name;
		$this->user->profile->description  	= @ $response->description;
		$this->user->profile->firstName  	= @ $response->name; 
		$this->user->profile->photoURL   	= @ $response->profile_image_url;
		$this->user->profile->profileURL 	= @ 'http://identi.ca/' . $response->screen_name;
		$this->user->profile->webSiteURL 	= @ $response->url; 
		$this->user->profile->address 		= @ $response->location;

		return $this->user->profile;
 	}
}
