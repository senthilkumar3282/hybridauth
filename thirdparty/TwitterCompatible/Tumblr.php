<?php 
	// well Tumblr is not that compatible but eh the authentification work the same
	class Tumblr_Client extends Twitter_Compatible_Client
	{
		/* Set up the API root URL. */
		public $host = "http://www.tumblr.com";

		/* Respons format. */
		public $format = 'xml';

		/* Set API URLS */ 
		function authenticateURL() { return 'http://www.tumblr.com/oauth/authorize'; } 
	}
