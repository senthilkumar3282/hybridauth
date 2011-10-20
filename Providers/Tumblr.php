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
* Hybrid_Providers_Tumblr class, wrapper for Tumblr auth/api 
*/
class Hybrid_Providers_Tumblr extends Hybrid_Provider_Model
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
		require_once Hybrid_Auth::$config["path_libraries"] . "TwitterCompatible/Tumblr.php";

		if( $this->token( "access_token" ) && $this->token( "access_token_secret" ) )
		{
			$this->api = new Tumblr_Client
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
 	    $this->api = new Tumblr_Client( $this->config["keys"]["key"], $this->config["keys"]["secret"] );

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
			$this->api = new Tumblr_Client( 
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
			$response = $this->api->get( 'http://www.tumblr.com/api/authenticate' );

			$response = @ new SimpleXMLElement( $response ); 

			// the easy way (well 4 me at least)
			$xml2array = @ $this->xml2array( $response );

			$this->user->profile->identifier    = @ (string) $xml2array["children"]["tumblelog"][0]["attr"]["url"]; 
			$this->user->profile->displayName  	= @ (string) $xml2array["children"]["tumblelog"][0]["attr"]["name"];
			$this->user->profile->profileURL 	= @ (string) $xml2array["children"]["tumblelog"][0]["attr"]["url"]; 
			$this->user->profile->webSiteURL 	= @ (string) $xml2array["children"]["tumblelog"][0]["attr"]["url"]; 
			$this->user->profile->photoURL   	= @ (string) $xml2array["children"]["tumblelog"][0]["attr"]["avatar-url"]; 
		}
		catch( Exception $e ){
			throw new Exception( "User profile request failed! {$this->providerId} returned an error while requesting the user profile.", 6 );
		}

		return $this->user->profile;
 	}

	function xml2array($xml) { 
		$arXML=array(); 
		$arXML['name']=trim($xml->getName()); 
		$arXML['value']=trim((string)$xml); 
		$t=array(); 
		foreach($xml->attributes() as $name => $value){ 
			$t[$name]=trim($value); 
		} 
		$arXML['attr']=$t; 
		$t=array(); 
		foreach($xml->children() as $name => $xmlchild) { 
			$t[$name][]=$this->xml2array($xmlchild); //FIX : For multivalued node 
		} 
		$arXML['children']=$t; 
		return($arXML); 
	} 
}
